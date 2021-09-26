package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/olivere/elastic"
	esConfig "github.com/olivere/elastic/config"
	"github.com/rs/zerolog/log"
	qrcode "github.com/skip2/go-qrcode"
)

type PDF struct {
	StartPage int
	URL       string
}

type CategoricalDatum struct {
	Name     string
	Category string
}

type InformationPiece struct {
	CategoricalDatum
}

type SideEffect struct {
	CategoricalDatum
}

type HealthcareProvider struct {
	CategoricalDatum
}

type DoNotTake struct {
	CategoricalDatum
}

type Storage struct {
	CategoricalDatum
}

type Ingredient struct {
	CategoricalDatum
}

type GeneralInformation struct {
	CategoricalDatum
}

type Leaflet struct {
	ActiveIngredient     string `json:"activeIngredient"`
	FormRoute            string `json:"formRoute"`
	ApplNo               string `json:"applNo"`
	Company              string `json:"company"`
	Date                 string `json:"date"`
	PDF                  PDF
	ImportantInformation []InformationPiece
	SideEffects          []SideEffect
	HealthcareProviders  []HealthcareProvider
	DoNotTake            []DoNotTake
	Storage              []Storage
	Ingredients          []Ingredient
	GeneralInformation   []GeneralInformation
}

type VerifySignatureRequest struct {
	SignedContent string `json:"signedContent"`
}

const (
	ELASTIC_URL         = "http://20.82.202.54:9200"
	LEAFLET_INDEX       = "leaflets"
	SIGNATURE_SEPARATOR = "(240)"
)

type SearchQuery struct {
	Bool SearchBool `json:"bool"`
}

type SearchBool struct {
	Should []SearchShould `json:"should"`
}

type SearchShould struct {
	Fuzzy map[string]NameValuePair `json:"fuzzy"`
}

type NameValuePair struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type MultiFuzzySearchQuery struct {
	Query SearchQuery `json:"query"`
	qs    string
}

func makeGS1String(gtin, lotno, exp, ser string) string {
	partial := fmt.Sprintf("(01)%s(17)%s(10)%s(21)%s", gtin, exp, lotno, ser)
	signed := signString(partial, "public.pem", "private.pem")
	return fmt.Sprintf("%s(240)%s", partial, signed)
}

func (m *MultiFuzzySearchQuery) SetTerm(term string) {
	m.qs = fmt.Sprintf(`{
		"query": {
			"bool": {
				"should": [
					{
						"fuzzy": {
							"name": {
								"value": "%s"
							}
						}
					},
					{
						"fuzzy": {
							"activeIngredient": {
								"value": "%s"
							}
						}
					}
				]
			}
		}
	}`, term, term)
}

func (m MultiFuzzySearchQuery) String() string {
	return m.qs
}

func (m MultiFuzzySearchQuery) Source() (interface{}, error) {
	if err := json.Unmarshal([]byte(m.qs), &m); err != nil {
		return nil, err
	}
	return m, nil
}

var (
	elasticClient *elastic.Client
	err           error
	ctx           context.Context
)

func init() {
	ctx = context.Background()
	config, _ := esConfig.Parse(ELASTIC_URL)
	elasticClient, _ = elastic.NewClientFromConfig(config)
	if err != nil {
		// Handle error
		panic(err)
	}
}

func main() {
	app := fiber.New()

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.SendStatus(204)
	})

	app.Get("/ready", func(c *fiber.Ctx) error {
		res, err := http.Get(ELASTIC_URL + "/" + LEAFLET_INDEX)
		if err != nil {
			panic(err)
		}
		return c.SendStatus(res.StatusCode)
	})

	app.Post("/verify", func(c *fiber.Ctx) error {
		vr := VerifySignatureRequest{}
		if err := c.BodyParser(&vr); err != nil {
			return err
		}

		log.Debug().Msg(vr.SignedContent)

		signedContent := strings.Split(vr.SignedContent, SIGNATURE_SEPARATOR)

		if err := verifySignature(signedContent[0], signedContent[1], "./public.pem"); err != nil {
			c.Context().SetStatusCode(400)
			return c.Send([]byte(err.Error()))
		}
		docId := strings.Replace(strings.Split(signedContent[0], "(21)")[1], "0000", "", 1)

		reqUrl := ELASTIC_URL + "/" + LEAFLET_INDEX + "/_doc/" + docId
		log.Debug().Msg(reqUrl)

		res, err := http.Get(reqUrl)
		if err != nil {
			c.Context().SetStatusCode(500)
			return c.Send([]byte(err.Error()))
		}
		bytesRead, _ := ioutil.ReadAll(res.Body)
		log.Debug().Msg(string(bytesRead))

		if res.StatusCode >= 400 {
			return c.SendStatus(res.StatusCode)
		}
		c.Context().SetContentType("application/json")
		return c.Send(bytesRead)
	})

	app.Get("/barcode/qr-gs1.png", func(c *fiber.Ctx) error {
		serial := c.Query("serial")
		str := makeGS1String("10857674002017", "NYFUL01", "141120", fmt.Sprintf("0000%s", serial))

		pngData, _ := qrcode.Encode(str, qrcode.Medium, 256)
		c.Request().Header.Set("Content-type", "image/png")
		return c.Send(pngData)
	})

	app.Get("/barcode/qr-gs1.txt", func(c *fiber.Ctx) error {
		serial := c.Query("serial")
		str := makeGS1String("10857674002017", "NYFUL01", "141120", fmt.Sprintf("0000%s", serial))
		return c.Send([]byte(str))
	})

	app.Use(cors.New())

	app.Get("/search", func(c *fiber.Ctx) error {
		q := c.Query("q")

		if len(q) < 3 {
			c.Context().SetStatusCode(400)
			return c.SendString("{\"reason\": \"query must be at least 3 char long\"}")
		}

		termQuery := MultiFuzzySearchQuery{}
		termQuery.SetTerm(q)

		log.Debug().Msg(termQuery.String())

		bodyReader := strings.NewReader(termQuery.String())
		req, err := http.NewRequest(http.MethodGet, ELASTIC_URL+"/"+LEAFLET_INDEX+"/_search", bodyReader)
		if err != nil {
			panic(err)
		}
		req.Header["Content-type"] = []string{"application/json"}
		res, err := http.DefaultClient.Do(req)

		bytesRead, _ := ioutil.ReadAll(res.Body)
		c.Context().SetContentType("application/json")
		return c.Send(bytesRead)
	})

	app.Listen(":3000")
}
