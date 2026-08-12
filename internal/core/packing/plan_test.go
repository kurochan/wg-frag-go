package packing

import (
	"testing"

	"github.com/kurochan/wg-frag-go/internal/core/limits"
)

func TestMakePlanFlushesTailThatWouldNeedSeventeenFragments(t *testing.T) {
	t.Parallel()
	plan, err := MakePlan(limits.MaxInnerMTU, limits.DefaultCarrierPayload, 140, limits.DefaultMinPackData)
	if err != nil {
		t.Fatal(err)
	}
	if plan.StartInTail {
		t.Fatalf("started in tail: %+v", plan)
	}
	if plan.Fragments != limits.MaxFragments {
		t.Fatalf("fragments = %d, want %d", plan.Fragments, limits.MaxFragments)
	}
}

func TestMakePlanUsesTailWhenItFits(t *testing.T) {
	t.Parallel()
	plan, err := MakePlan(1000, limits.DefaultCarrierPayload, 200, limits.DefaultMinPackData)
	if err != nil {
		t.Fatal(err)
	}
	if !plan.StartInTail || plan.FirstData != 188 || plan.Fragments != 3 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
}
