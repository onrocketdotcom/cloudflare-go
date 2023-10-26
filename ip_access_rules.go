package cloudflare

import (
	"context"
	"fmt"
	"net/http"

	"github.com/goccy/go-json"
)

type ListIpAccessRulesOrderOption string
type ListIpAccessRulesMatchOption string
type RulesModeOption string

const (
	ConfigurationTarget      ListIpAccessRulesOrderOption = "configuration.target"
	ConfigurationValue       ListIpAccessRulesOrderOption = "configuration.value"
	Mode                     ListIpAccessRulesOrderOption = "mode"
	MatchOptionAll           ListIpAccessRulesMatchOption = "all"
	MatchOptionAny           ListIpAccessRulesMatchOption = "any"
	RuleModeBlock            RulesModeOption              = "block"
	RuleModeChallenge        RulesModeOption              = "challenge"
	RuleModeJsChallenge      RulesModeOption              = "js_challenge"
	RuleModeManagedChallenge RulesModeOption              = "managed_challenge"
	RuleModeWhitelist        RulesModeOption              = "whitelist"
)

type EGSPaginationJSON struct {
	Page    int `url:"page,omitempty"`
	PerPage int `url:"per_page,omitempty"`
}

type ListIpAccessRulesFilters struct {
	ConfigurationTarget string                       `json:"configuration.target,omitempty"`
	ConfigurationValue  string                       `json:"configuration.value,omitempty"`
	Match               ListIpAccessRulesMatchOption `json:"match,omitempty"`
	Mode                RulesModeOption              `json:"mode,omitempty"`
	Notes               string                       `json:"notes,omitempty"`
}

type ListIpAccessRulesParams struct {
	Direction         string                       `url:"direction,omitempty"`
	EGSPaginationJSON EGSPaginationJSON            `url:"egs-pagination.json,omitempty"`
	Filters           ListIpAccessRulesFilters     `url:"filters,omitempty"`
	Order             ListIpAccessRulesOrderOption `url:"order,omitempty"`
	Page              int                          `url:"page,omitempty"`
	PerPage           int                          `url:"per_page,omitempty"`
}

type IPAccessRuleConfiguration struct {
	Target string `json:"target"`
	Value  string `json:"value"`
}

type IpAccessRule struct {
	AllowedModes  []RulesModeOption         `json:"allowed_modes"`
	Configuration IPAccessRuleConfiguration `json:"configuration"`
	CreatedOn     string                    `json:"created_on"`
	ID            string                    `json:"id"`
	Mode          RulesModeOption           `json:"mode"`
	ModifiedOn    string                    `json:"modified_on"`
	Notes         string                    `json:"notes"`
}

type ListIpAccessRulesResponse struct {
	Result     []IpAccessRule `json:"result"`
	ResultInfo `json:"result_info"`
	Response
}

// ListIpAccessRules
//
// Fetches IP Access rules of a zone. You can filter the results using several optional parameters.
//
// API reference: https://developers.cloudflare.com/api/operations/ip-access-rules-for-a-zone-list-ip-access-rules
func (api *API) ListIpAccessRules(ctx context.Context, rc *ResourceContainer, params ListIpAccessRulesParams) ([]IpAccessRule, error) {

	if rc.Identifier == "" {
		return []IpAccessRule{}, ErrMissingZoneID
	}

	uri := buildURI(fmt.Sprintf("/zones/%s/firewall/access_rules/rules", rc.Identifier), params)

	res, err := api.makeRequestContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return []IpAccessRule{}, err
	}

	result := ListIpAccessRulesResponse{}

	err = json.Unmarshal(res, &result)
	if err != nil {
		return []IpAccessRule{}, fmt.Errorf("%s: %w", errUnmarshalError, err)
	}

	return result.Result, nil
}
