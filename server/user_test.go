package main

import (
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/tinode/chat/server/store"
	mock_store "github.com/tinode/chat/server/store/mock_store"
	"github.com/tinode/chat/server/store/types"
)

type testValidator struct{}

func (*testValidator) Init(string) error { return nil }

func (*testValidator) IsInitialized() bool { return true }

func (*testValidator) PreCheck(string, map[string]any) (string, error) { return "", nil }

func (*testValidator) Request(types.Uid, string, string, string, []byte) (bool, error) {
	return true, nil
}

func (*testValidator) ResetSecret(string, string, string, []byte, map[string]any) error { return nil }

func (*testValidator) Check(types.Uid, string) (string, error) { return "", nil }

func (*testValidator) Remove(types.Uid, string) error { return nil }

func (*testValidator) Delete(types.Uid) error { return nil }

func (*testValidator) TempAuthScheme() (string, error) { return "code", nil }

func TestAddCredsAutovalidate(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	oldStore := store.Store
	oldUsers := store.Users
	oldValidators := globals.validators
	defer func() {
		store.Store = oldStore
		store.Users = oldUsers
		globals.validators = oldValidators
	}()

	mockPersistentStore := mock_store.NewMockPersistentStorageInterface(ctrl)
	mockUsers := mock_store.NewMockUsersPersistenceInterface(ctrl)
	store.Store = mockPersistentStore
	store.Users = mockUsers

	globals.validators = map[string]credValidator{
		"email": {
			addToTags:    true,
			autovalidate: true,
		},
		"tel": {
			addToTags:    true,
			autovalidate: true,
		},
	}

	uid := types.Uid(42)
	emailValidator := &testValidator{}
	telValidator := &testValidator{}

	mockPersistentStore.EXPECT().GetValidator("email").Return(emailValidator)
	mockPersistentStore.EXPECT().GetValidator("tel").Return(telValidator)
	mockUsers.EXPECT().ConfirmCred(uid, "email").Return(nil)
	mockUsers.EXPECT().ConfirmCred(uid, "tel").Return(nil)
	mockUsers.EXPECT().
		UpdateTags(uid, []string{"email:test@example.com", "tel:+15551234567"}, nil, nil).
		Return([]string{"email:test@example.com", "tel:+15551234567"}, nil)

	validated, tags, err := addCreds(uid, []MsgCredClient{
		{Method: "email", Value: "test@example.com", Response: "123456"},
		{Method: "tel", Value: "+15551234567", Response: "654321"},
	}, nil, "en", []byte("tmp-token"))
	if err != nil {
		t.Fatalf("addCreds returned error: %v", err)
	}

	if len(validated) != 2 || validated[0] != "email" || validated[1] != "tel" {
		t.Fatalf("validated=%v, want [email tel]", validated)
	}

	if len(tags) != 2 || tags[0] != "email:test@example.com" || tags[1] != "tel:+15551234567" {
		t.Fatalf("tags=%v, want [email:test@example.com tel:+15551234567]", tags)
	}
}
