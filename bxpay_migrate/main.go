package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/jszwec/csvutil"
	"github.com/openebl/openebl/pkg/bu_server/business_unit"
	"github.com/openebl/openebl/pkg/bu_server/model"
	"github.com/openebl/openebl/pkg/cert_server/cert_authority"
	cert_model "github.com/openebl/openebl/pkg/cert_server/model"
	"github.com/openebl/openebl/pkg/did"
	eblpkix "github.com/openebl/openebl/pkg/pkix"
	"github.com/openebl/openebl/pkg/util"
	"github.com/samber/lo"
	"gopkg.in/yaml.v2"
)

type Record struct {
	ID          string `csv:"id"`
	Name        string `csv:"name"`
	State       string `csv:"state"`
	CreatedAt   string `csv:"created_at"`
	UpdatedAt   string `csv:"updated_at"`
	ShortName   string `csv:"short_name"`
	TaxID       string `csv:"tax_id"`
	Address1    string `csv:"address1"`
	Address2    string `csv:"address2"`
	City        string `csv:"city"`
	USState     string `csv:"us_state"`
	Zipcode     string `csv:"zipcode"`
	Country     string `csv:"country"`
	Notes       string `csv:"notes"`
	ExternalID  string `csv:"external_id"`
	CompanyType string `csv:"company_type"`
	Emails      string `csv:"emails"`

	BUId         string `csv:"bu_id"`
	BUAuthID     string `csv:"bu_auth_id"`
	BUAuthCertID string `csv:"bu_auth_cert_id"`
	BUAuthCert   string `csv:"bu_auth_cert"`
}

type Config struct {
	ApplicationKey      string `yaml:"application_key"`
	BUServerURL         string `yaml:"bu_server_url"`
	CertAuthorityURL    string `yaml:"cert_authority_url"`
	CertAuthorityCertID string `yaml:"cert_authority_cert_id"`
	CertValidDuration   int    `yaml:"cert_valid_duration"`
}

var config Config

func init() {
	file, err := os.Open("config.yaml")
	if err != nil {
		log.Fatalf("failed to open config file: %v", err)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("failed to decode config: %v", err)
	}
}

func main() {
	csvSource, err := os.ReadFile("migration.csv")
	if err != nil {
		panic(err)
	}

	var records []*Record
	if err := csvutil.Unmarshal(csvSource, &records); err != nil {
		panic(err)
	}

	for _, record := range records {
		fmt.Printf("%s begins.\n", record.Name)
		for {
			err := migrate(record)
			if errors.Is(os.ErrProcessDone, err) {
				break
			} else if err != nil {
				panic(err)
			}

			csvData, err := csvutil.Marshal(records)
			if err != nil {
				panic(err)
			}

			err = os.WriteFile("migration.csv", csvData, 0644)
			if err != nil {
				panic(err)
			}
		}
		fmt.Printf("%s ends.\n", record.Name)
	}
}

func migrate(record *Record) error {
	switch {
	case record.BUId == "":
		err := createBusinessUnit(record)
		if err != nil {
			return err
		}
	case record.BUAuthID == "":
		err := createBusinessUnitAuthentication(record)
		if err != nil {
			return err
		}
	case record.BUAuthCertID == "":
		err := deliverCSR(record)
		if err != nil {
			return err
		}
	case record.BUAuthCert == "":
		err := issueCert(record)
		if err != nil {
			return err
		}
	default:
		return os.ErrProcessDone
	}

	return nil
}

func createBusinessUnit(record *Record) error {
	// Create a new `Business Unit` under the `application` in `BU Server`
	// Write back the `Business Unit ID` back to the record.BUId

	getAddress := func(record *Record) string {
		addressLines := []string{}
		addressLines = append(addressLines, strings.TrimSpace(record.Address1))
		if record.Address2 != "" {
			addressLines = append(addressLines, strings.TrimSpace(record.Address2))
		}
		addressLines = append(addressLines, strings.TrimSpace(record.City))
		addressLines = append(addressLines, strings.TrimSpace(record.USState))
		addressLines = append(addressLines, strings.TrimSpace(record.Zipcode))
		addressLines = lo.Filter(addressLines, func(line string, _ int) bool {
			return line != ""
		})

		address := strings.Join(addressLines, ", ")
		return address
	}

	getEmails := func(record *Record) []string {
		emails := strings.Split(strings.Trim(record.Emails, "{}"), ",")
		return emails
	}

	restReq := business_unit.CreateBusinessUnitRequest{
		Requester: "BlueX Pay Migrator",
		Name:      record.Name,
		Addresses: []string{getAddress(record)},
		Country:   record.Country,
		Emails:    getEmails(record),
		Status:    model.BusinessUnitStatusActive,
	}

	jsonReq, err := json.Marshal(restReq)
	if err != nil {
		return err
	}

	buCreateEndPoint := fmt.Sprintf("%s/business_unit", config.BUServerURL)
	req, err := http.NewRequest("POST", buCreateEndPoint, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.ApplicationKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create business unit, status code: %d. %s", resp.StatusCode, string(body))
	}

	buResp := model.BusinessUnit{}
	err = json.NewDecoder(resp.Body).Decode(&buResp)
	if err != nil {
		return err
	}
	record.BUId = buResp.ID.String()

	return nil
}

func createBusinessUnitAuthentication(record *Record) error {
	// Create a `BusinessUnitAuthentication` for the `Business Unit` in `BU Server`
	// Write back the `Business Unit Authentication ID` back to the record.BUAuthID

	restReq := business_unit.AddAuthenticationRequest{
		Requester:        "BlueX Pay Migrator",
		PrivateKeyOption: eblpkix.PrivateKeyOption{KeyType: "RSA", BitLength: 4096},
		BusinessUnitID:   did.MustParse(record.BUId),
	}

	jsonReq, err := json.Marshal(restReq)
	if err != nil {
		return err
	}

	buAuthEndPoint := fmt.Sprintf("%s/business_unit/%s/authentication", config.BUServerURL, record.BUId)
	req, err := http.NewRequest("POST", buAuthEndPoint, bytes.NewBuffer(jsonReq))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.ApplicationKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to create business unit authentication, status code: %d. %s", resp.StatusCode, string(body))
	}

	buAuthResp := model.BusinessUnitAuthentication{}
	err = json.NewDecoder(resp.Body).Decode(&buAuthResp)
	if err != nil {
		return err
	}
	record.BUAuthID = buAuthResp.ID
	return nil
}

func deliverCSR(record *Record) error {
	// Deliver the `CSR` of `BusinessUnitAuthentication` to the cert authority via `POST /cert`
	// Write the `Cert ID` back to the record.BUAuthCertID

	buAuthEndPoint := fmt.Sprintf("%s/business_unit/%s/authentication/%s", config.BUServerURL, record.BUId, record.BUAuthID)
	req, err := http.NewRequest("GET", buAuthEndPoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.ApplicationKey))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to get business unit authentication, status code: %d. %s", resp.StatusCode, string(body))
	}

	buAuthResp := model.BusinessUnitAuthentication{}
	err = json.NewDecoder(resp.Body).Decode(&buAuthResp)
	if err != nil {
		return err
	}

	certRequest := cert_authority.AddCertificateSigningRequestRequest{
		CertType:           cert_model.BUCert,
		CertSigningRequest: buAuthResp.CertificateSigningRequest,
	}

	csrEndpoint := fmt.Sprintf("%s/cert", config.CertAuthorityURL)
	csrReq, err := http.NewRequest("POST", csrEndpoint, util.StructToJSONReader(certRequest))
	if err != nil {
		return err
	}
	csrReq.Header.Set("X-Requester", "BlueX Pay Migrator")

	csrResp, err := client.Do(csrReq)
	if err != nil {
		return err
	}
	defer csrResp.Body.Close()

	if csrResp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(csrResp.Body)
		return fmt.Errorf("failed to deliver CSR, status code: %d. %s", csrResp.StatusCode, string(body))
	}

	certResp := cert_model.Cert{}
	err = json.NewDecoder(csrResp.Body).Decode(&certResp)
	if err != nil {
		return err
	}
	record.BUAuthCertID = certResp.ID

	return nil
}

func issueCert(record *Record) error {
	// Issue the `Cert` of `BusinessUnitAuthentication` via `POST /cert/{cert_id}`
	// Write the `Cert` back to the record.BUAuthCert

	ts := time.Now().Unix()
	restReq := cert_authority.IssueCertificateRequest{
		CACertID:  config.CertAuthorityCertID,
		CertType:  cert_model.BUCert,
		NotBefore: ts,
		NotAfter:  ts + 86400*int64(config.CertValidDuration),
	}

	client := &http.Client{}
	issueEndpoint := fmt.Sprintf("%s/cert/%s", config.CertAuthorityURL, record.BUAuthCertID)
	issueReq, err := http.NewRequest("POST", issueEndpoint, util.StructToJSONReader(restReq))
	if err != nil {
		return err
	}
	issueReq.Header.Set("X-Requester", "BlueX Pay Migrator")

	issueResp, err := client.Do(issueReq)
	if err != nil {
		return err
	}
	defer issueResp.Body.Close()

	if issueResp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(issueResp.Body)
		return fmt.Errorf("failed to issue certificate, status code: %d. %s", issueResp.StatusCode, string(body))
	}

	certResp := cert_model.Cert{}
	err = json.NewDecoder(issueResp.Body).Decode(&certResp)
	if err != nil {
		return err
	}
	record.BUAuthCert = certResp.Certificate

	return nil
}
