package controllerservice

import (
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

const (
	auditCursorVersion = byte(1)
	auditCursorGlobal  = byte(0)
	auditCursorNetwork = byte(1)
	auditCursorBytes   = 2 + identity.IDSize + 8 + identity.IDSize
)

type auditPageResponse struct {
	Events     []auditResponse `json:"events"`
	NextCursor string          `json:"next_cursor,omitempty"`
}

func parseAuditPageRequest(r *http.Request, networkID *identity.NetworkID) (int, *controller.AuditPageCursor, error) {
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return 0, nil, malformed("audit query is malformed")
	}
	for key := range query {
		if key != "limit" && key != "cursor" {
			return 0, nil, malformed("audit query supports only limit and cursor")
		}
	}
	if len(query["limit"]) > 1 || len(query["cursor"]) > 1 {
		return 0, nil, malformed("audit query parameters must not be repeated")
	}
	limit := 100
	if values, present := query["limit"]; present && values[0] != "" {
		limit, err = strconv.Atoi(values[0])
		if err != nil || limit < 1 || limit > 1000 {
			return 0, nil, malformed("limit must be an integer from 1 through 1000")
		}
	}
	values, present := query["cursor"]
	if !present {
		return limit, nil, nil
	}
	if len(values) != 1 || values[0] == "" {
		return 0, nil, malformed("cursor must be a non-empty opaque audit cursor")
	}
	cursor, err := decodeAuditCursor(values[0], networkID)
	if err != nil {
		return 0, nil, err
	}
	return limit, cursor, nil
}

func encodeAuditCursor(cursor *controller.AuditPageCursor, networkID *identity.NetworkID) string {
	if cursor == nil {
		return ""
	}
	encoded := make([]byte, auditCursorBytes)
	encoded[0] = auditCursorVersion
	if networkID != nil {
		encoded[1] = auditCursorNetwork
		copy(encoded[2:2+identity.IDSize], networkID[:])
	} else {
		encoded[1] = auditCursorGlobal
	}
	binary.BigEndian.PutUint64(encoded[2+identity.IDSize:2+identity.IDSize+8], uint64(cursor.CreatedAt.Unix()))
	copy(encoded[2+identity.IDSize+8:], cursor.ID[:])
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func decodeAuditCursor(raw string, networkID *identity.NetworkID) (*controller.AuditPageCursor, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(decoded) != auditCursorBytes || decoded[0] != auditCursorVersion ||
		base64.RawURLEncoding.EncodeToString(decoded) != raw {
		return nil, malformed("cursor is not a valid opaque audit cursor")
	}
	var encodedNetwork identity.NetworkID
	copy(encodedNetwork[:], decoded[2:2+identity.IDSize])
	if networkID == nil {
		if decoded[1] != auditCursorGlobal || !encodedNetwork.IsZero() {
			return nil, malformed("cursor does not belong to this audit scope")
		}
	} else if decoded[1] != auditCursorNetwork || encodedNetwork != *networkID {
		return nil, malformed("cursor does not belong to this audit scope")
	}
	createdAtUnix := int64(binary.BigEndian.Uint64(decoded[2+identity.IDSize : 2+identity.IDSize+8]))
	if createdAtUnix < 0 {
		return nil, malformed("cursor is not a valid opaque audit cursor")
	}
	var id identity.ID
	copy(id[:], decoded[2+identity.IDSize+8:])
	if id.IsZero() {
		return nil, malformed("cursor is not a valid opaque audit cursor")
	}
	return &controller.AuditPageCursor{CreatedAt: time.Unix(createdAtUnix, 0).UTC(), ID: id}, nil
}
