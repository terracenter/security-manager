// Package store provee persistencia SQLite embebida para el estado de SM-NG
// que necesita orden explícito (ej. reglas forward estilo MikroTik, donde la
// posición determina cuál regla gana primero). El resto de SM-NG sigue en
// archivos .conf pipe-delimited (whitelist/immune/blacklist/allowed_ports) —
// no es parte de este paquete migrarlos.
//
// Driver puro Go (modernc.org/sqlite, sin cgo) para preservar el binario
// estático (CGO_ENABLED=0).
package store

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// ForwardRule es una regla del motor forward estilo MikroTik:
// (src, dst, port_range, proto) -> action, evaluada en orden de Position
// (primera coincidencia gana, igual que /ip firewall filter de RouterOS).
type ForwardRule struct {
	ID          int64
	Position    int64
	Src         string // CIDR v4/v6, "" = any
	Dst         string // CIDR v4/v6, "" = any
	PortRange   string // "22" | "8000-9000" | "" = any
	Proto       string // "tcp" | "udp" | "" (obligatorio si PortRange != "")
	Action      string // "accept" | "drop"
	Comment     string
	Responsable string
	CreatedAt   string
}

// DB envuelve la conexión SQLite y expone el repositorio de SM-NG.
type DB struct {
	sql *sql.DB
}

// Open abre (o crea) la base en path y aplica el esquema. El caller debe
// llamar Close().
func Open(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: abrir %s: %w", path, err)
	}
	db := &DB{sql: sqlDB}
	if err := db.migrate(); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return db, nil
}

func (db *DB) Close() error {
	return db.sql.Close()
}

func (db *DB) migrate() error {
	const schema = `
CREATE TABLE IF NOT EXISTS forward_rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    position    INTEGER NOT NULL,
    src         TEXT,
    dst         TEXT,
    port_range  TEXT,
    proto       TEXT,
    action      TEXT NOT NULL,
    comment     TEXT,
    responsable TEXT,
    created_at  TEXT NOT NULL
);

-- Genérica a propósito: entity_type hoy solo tiene 'forward_rule', preparada
-- para que whitelist/blacklist/immune la adopten en una migración futura
-- (visión de tags estilo GCP, ver Planes/Security-Manager-NG/caracteristicas/
-- vision-tags-multihost-gcp-style.md) sin rediseño de esquema.
CREATE TABLE IF NOT EXISTS tags (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id   INTEGER NOT NULL,
    tag         TEXT NOT NULL,
    UNIQUE(entity_type, entity_id, tag)
);
`
	if _, err := db.sql.Exec(schema); err != nil {
		return fmt.Errorf("store: migrar esquema: %w", err)
	}
	return nil
}

// AddForwardRule inserta una regla al final del orden actual (position =
// MAX(position)+1) y retorna su ID.
func (db *DB) AddForwardRule(r ForwardRule) (int64, error) {
	tx, err := db.sql.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var maxPos sql.NullInt64
	if err := tx.QueryRow(`SELECT MAX(position) FROM forward_rules`).Scan(&maxPos); err != nil {
		return 0, fmt.Errorf("store: leer max(position): %w", err)
	}
	nextPos := int64(1)
	if maxPos.Valid {
		nextPos = maxPos.Int64 + 1
	}

	res, err := tx.Exec(
		`INSERT INTO forward_rules (position, src, dst, port_range, proto, action, comment, responsable, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
		nextPos, r.Src, r.Dst, r.PortRange, r.Proto, r.Action, r.Comment, r.Responsable,
	)
	if err != nil {
		return 0, fmt.Errorf("store: insertar regla: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: leer id insertado: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit: %w", err)
	}
	return id, nil
}

// ListForwardRules retorna las reglas ordenadas por Position (orden de
// evaluación). Si tag != "", filtra solo las reglas con ese tag.
func (db *DB) ListForwardRules(tag string) ([]ForwardRule, error) {
	query := `SELECT id, position, src, dst, port_range, proto, action, comment, responsable, created_at
	          FROM forward_rules`
	args := []any{}
	if tag != "" {
		query += ` WHERE id IN (SELECT entity_id FROM tags WHERE entity_type = 'forward_rule' AND tag = ?)`
		args = append(args, tag)
	}
	query += ` ORDER BY position ASC`

	rows, err := db.sql.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("store: listar reglas: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []ForwardRule
	for rows.Next() {
		var r ForwardRule
		if err := rows.Scan(&r.ID, &r.Position, &r.Src, &r.Dst, &r.PortRange, &r.Proto,
			&r.Action, &r.Comment, &r.Responsable, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("store: leer fila: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteForwardRule elimina la regla por ID. No renumera las posiciones
// restantes (el orden relativo entre las reglas que quedan no cambia).
func (db *DB) DeleteForwardRule(id int64) error {
	res, err := db.sql.Exec(`DELETE FROM forward_rules WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: borrar regla %d: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: confirmar borrado %d: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("store: no existe la regla %d", id)
	}
	return nil
}

// MoveForwardRule reubica la regla id a la posición newPos (1-based, en el
// orden de evaluación), renumerando el resto de forma transaccional.
func (db *DB) MoveForwardRule(id int64, newPos int64) error {
	if newPos < 1 {
		return fmt.Errorf("store: posición inválida %d (mínimo 1)", newPos)
	}
	tx, err := db.sql.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.Query(`SELECT id FROM forward_rules WHERE id != ? ORDER BY position ASC`, id)
	if err != nil {
		return fmt.Errorf("store: leer orden actual: %w", err)
	}
	var others []int64
	for rows.Next() {
		var otherID int64
		if err := rows.Scan(&otherID); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store: leer fila de orden: %w", err)
		}
		others = append(others, otherID)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return err
	}
	_ = rows.Close()

	if newPos > int64(len(others))+1 {
		newPos = int64(len(others)) + 1
	}

	// Reconstruir el orden completo insertando `id` en newPos-1 (0-based).
	ordered := make([]int64, 0, len(others)+1)
	ordered = append(ordered, others[:newPos-1]...)
	ordered = append(ordered, id)
	ordered = append(ordered, others[newPos-1:]...)

	for i, rid := range ordered {
		if _, err := tx.Exec(`UPDATE forward_rules SET position = ? WHERE id = ?`, i+1, rid); err != nil {
			return fmt.Errorf("store: renumerar regla %d: %w", rid, err)
		}
	}
	return tx.Commit()
}

// AddTag asocia tag a una entidad (entityType, entityID). Idempotente
// (UNIQUE constraint — un tag repetido no es error).
func (db *DB) AddTag(entityType string, entityID int64, tag string) error {
	_, err := db.sql.Exec(
		`INSERT OR IGNORE INTO tags (entity_type, entity_id, tag) VALUES (?, ?, ?)`,
		entityType, entityID, tag,
	)
	if err != nil {
		return fmt.Errorf("store: agregar tag %q: %w", tag, err)
	}
	return nil
}

// TagsFor retorna los tags asociados a una entidad.
func (db *DB) TagsFor(entityType string, entityID int64) ([]string, error) {
	rows, err := db.sql.Query(
		`SELECT tag FROM tags WHERE entity_type = ? AND entity_id = ? ORDER BY tag ASC`,
		entityType, entityID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: leer tags: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, fmt.Errorf("store: leer tag: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
