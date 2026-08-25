package store

import "testing"

func openTestDB(t *testing.T) *DB {
	t.Helper()
	// file::memory: con cache=shared para que la MISMA base sobreviva
	// mientras el *sql.DB tenga el pool abierto (":memory:" a secas crea
	// una conexión nueva/vacía por cada conexión del pool).
	db, err := Open("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAddAndListForwardRules_PreservesOrder(t *testing.T) {
	db := openTestDB(t)

	id1, err := db.AddForwardRule(ForwardRule{Src: "172.17.0.0/16", Action: "drop"})
	if err != nil {
		t.Fatalf("AddForwardRule #1: %v", err)
	}
	id2, err := db.AddForwardRule(ForwardRule{Src: "10.0.0.0/8", Action: "accept"})
	if err != nil {
		t.Fatalf("AddForwardRule #2: %v", err)
	}

	rules, err := db.ListForwardRules("")
	if err != nil {
		t.Fatalf("ListForwardRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("esperaba 2 reglas, obtuve %d", len(rules))
	}
	if rules[0].ID != id1 || rules[1].ID != id2 {
		t.Errorf("orden incorrecto: [%d,%d], esperaba [%d,%d]", rules[0].ID, rules[1].ID, id1, id2)
	}
	if rules[0].Position >= rules[1].Position {
		t.Errorf("position no ascendente: %d, %d", rules[0].Position, rules[1].Position)
	}
}

func TestMoveForwardRule_RenumbersWithoutDuplicates(t *testing.T) {
	db := openTestDB(t)

	id1, _ := db.AddForwardRule(ForwardRule{Src: "a", Action: "drop"})
	id2, _ := db.AddForwardRule(ForwardRule{Src: "b", Action: "drop"})
	id3, _ := db.AddForwardRule(ForwardRule{Src: "c", Action: "drop"})

	if err := db.MoveForwardRule(id3, 1); err != nil {
		t.Fatalf("MoveForwardRule: %v", err)
	}

	rules, err := db.ListForwardRules("")
	if err != nil {
		t.Fatalf("ListForwardRules: %v", err)
	}
	if len(rules) != 3 {
		t.Fatalf("esperaba 3 reglas, obtuve %d", len(rules))
	}
	got := []int64{rules[0].ID, rules[1].ID, rules[2].ID}
	want := []int64{id3, id1, id2}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("orden tras move = %v, esperaba %v", got, want)
			break
		}
	}
	seen := map[int64]bool{}
	for _, r := range rules {
		if seen[r.Position] {
			t.Errorf("position %d duplicada tras move", r.Position)
		}
		seen[r.Position] = true
	}
}

func TestDeleteForwardRule_NoGapsBreakListing(t *testing.T) {
	db := openTestDB(t)

	id1, _ := db.AddForwardRule(ForwardRule{Src: "a", Action: "drop"})
	id2, _ := db.AddForwardRule(ForwardRule{Src: "b", Action: "drop"})
	id3, _ := db.AddForwardRule(ForwardRule{Src: "c", Action: "drop"})

	if err := db.DeleteForwardRule(id2); err != nil {
		t.Fatalf("DeleteForwardRule: %v", err)
	}

	rules, err := db.ListForwardRules("")
	if err != nil {
		t.Fatalf("ListForwardRules: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("esperaba 2 reglas, obtuve %d", len(rules))
	}
	if rules[0].ID != id1 || rules[1].ID != id3 {
		t.Errorf("orden tras delete = [%d,%d], esperaba [%d,%d]", rules[0].ID, rules[1].ID, id1, id3)
	}
}

func TestDeleteForwardRule_UnknownID(t *testing.T) {
	db := openTestDB(t)
	if err := db.DeleteForwardRule(999); err == nil {
		t.Error("esperaba error al borrar ID inexistente")
	}
}

func TestAddTag_UniqueAndFilterable(t *testing.T) {
	db := openTestDB(t)

	id, _ := db.AddForwardRule(ForwardRule{Src: "172.17.0.0/16", Action: "drop"})
	other, _ := db.AddForwardRule(ForwardRule{Src: "10.0.0.0/8", Action: "accept"})

	if err := db.AddTag("forward_rule", id, "docker-containment"); err != nil {
		t.Fatalf("AddTag: %v", err)
	}
	if err := db.AddTag("forward_rule", id, "docker-containment"); err != nil {
		t.Fatalf("AddTag repetido no debe fallar (idempotente): %v", err)
	}

	tags, err := db.TagsFor("forward_rule", id)
	if err != nil {
		t.Fatalf("TagsFor: %v", err)
	}
	if len(tags) != 1 || tags[0] != "docker-containment" {
		t.Errorf("TagsFor = %v, esperaba [docker-containment]", tags)
	}

	filtered, err := db.ListForwardRules("docker-containment")
	if err != nil {
		t.Fatalf("ListForwardRules con tag: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != id {
		t.Errorf("ListForwardRules(tag) = %v, esperaba solo la regla %d", filtered, id)
	}
	_ = other
}
