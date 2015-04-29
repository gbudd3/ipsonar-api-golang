/*
This package wraps the IPsonar API to make it easier to use from Go
*/
package ipsonar

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"syscall"
	"time"
)

//===========================================================
// Stores the results of parsing the command line
type Command_line_parameters struct {
	Username  string
	Password  string
	Server    string
	Report_id int
	Cert_file string
	Local     bool
	Verbose   bool
}

// Struct for Lumeta custom attributes
type CustomAttribute struct {
	CIDR  string
	Name  string
	Value string
}

/*
This function parses the command line to gather various IPsonar
specific parameters.  This should be sufficient for a standalone
script, but you'll probably want to replace this with something
specific to your own application if you want anything more complicated.

*/
func Parse_command_line() Command_line_parameters {
	var params Command_line_parameters
	flag.StringVar(&params.Username, "u", "admin", "Username")
	flag.StringVar(&params.Username, "user", "admin", "Username")

	flag.StringVar(&params.Password, "p", "admin", "Password")
	flag.StringVar(&params.Password, "password", "admin", "Password")

	flag.StringVar(&params.Server, "s", "", "Server")
	flag.StringVar(&params.Server, "server", "", "Server")

	flag.IntVar(&params.Report_id, "r", 0, "Report number")
	flag.IntVar(&params.Report_id, "report", 0, "Report number")

	flag.StringVar(&params.Cert_file, "c", "", "Certificate File")
	flag.StringVar(&params.Cert_file, "cert", "", "Certificate File")

	flag.BoolVar(&params.Local, "l", false, "Run locally")
	flag.BoolVar(&params.Local, "local", false, "Run locally")

	flag.BoolVar(&params.Verbose, "v", false, "Verbose")
	flag.BoolVar(&params.Verbose, "verbose", false, "Verbose")

	flag.Parse()

	if len(params.Server) == 0 && !params.Local {
		fmt.Println("Server name (-s) or -l (local server) required")
		syscall.Exit(2)
	}

	return params
}

//===========================================================
type server struct {
	query                                       func(string) io.ReadCloser
	post                                        func(string, string, *bytes.Buffer) (io.ReadCloser, error)
	data                                        []interface{}
	pageSize, currentPage, row, maxRow, maxPage int
	parameters                                  Query
	queryUrl                                    string
	dataReady                                   bool
	serverError                                 error
}

//-----------------------------------------------------------

/*
The various NewServer functions should return one of these
*/
type Server interface {
	Query(call string, parameters Query) (int, error)
	/* Run this function over each item the Query returns */
	Each(each_func func(Data))
	Next() Data
	Count() int
	Copy() server
	WaitForReport(d time.Duration) chan *Report
	ServerError() error
	WriteReportAttributes(attributes []CustomAttribute, reportID string) error
	ClearReportAttributes(attributeName, reportID string) error
	Reports() ([]*Report, error)
}

// Return a slice of the reports on a RSN
// Sorted in descending report number
func (s *server) Reports() ([]*Report, error) {
	reports := make([]*Report, 0)
	s2 := s.Copy()
	_, err := s2.Query("config.reports", Query{})
	if err != nil {
		return nil, err
	}
	s2.Each(func(item Data) {
		rx := regexp.MustCompile(`\@Date\((\d+)\)`)
		x, _ := strconv.Atoi(rx.FindStringSubmatch(item.String("timestamp"))[1])
		x64 := uint64(x)
		r := Report{
			Id:        item.Int("id"),
			Ipcount:   item.Int("ipcount"),
			Name:      item.String("name"),
			Tag:       item.String("tag"),
			Timestamp: time.Unix(int64(x64/1000), int64((x64%1000)*1000)),
			Title:     item.String("title"),
		}
		reports = append(reports, &r)
	})
	sort.Sort(ByIdDesc{reports})
	return reports, nil
}

//-----------------------------------------------------------
// Get the last error seen during a server query
func (s *server) ServerError() error {
	return s.serverError
}

//-----------------------------------------------------------
// Returns a copy of this server
func (s *server) Copy() server {
	n := new(server)
	*n = *s
	return *n
}

//-----------------------------------------------------------
func (s *server) getPage(pageNum int) {
	s.serverError = nil
	queryUrl := s.queryUrl + fmt.Sprintf("&q.page=%d", pageNum)

	reader := s.query(queryUrl)
	defer reader.Close()

	decoder := json.NewDecoder(reader)

	var data map[string]interface{}
	if err := decoder.Decode(&data); err != nil {
		//TODO Clean this up, but it works for now
		b := make([]byte, 100000)
		fmt.Println(err)
		_, _ = io.ReadFull(s.query(s.queryUrl), b)
		s.serverError = errors.New(fmt.Sprintf("%s", b))
		return
	}

	results := data["results"].(map[string]interface{})
	var count int
	switch value := results["@total"].(type) {
	case float64:
		count = int(value)
	default:
		count = 0
	}

	if count == 0 {
		s.maxRow = 0
	} else {
		s.maxRow = count - 1
	}

	s.currentPage = pageNum
	s.data = results["items"].([]interface{})
}

//-----------------------------------------------------------

/*
Performs a call to the IPsonar server
call       = IPsonar call (e.g. "detail.devices")
parameters = a map of IPsonar parameters and values.

Example:
        _, _ = rsn.Query("detail.devices", api.Query{
                "q.details":         "Labels",
                "q.f.report.id":     report_id,
                "q.f.switch.switch": "true",
        })
*/
func (s *server) Query(call string, parameters Query) (int, error) {
	queryUrl := fmt.Sprintf("reporting/api/service/%s?fmt=json", call)

	if parameters != nil {
		// Set default q.pageSize
		if _, ok := parameters["q.pageSize"]; !ok {
			parameters["q.pageSize"] = "1000"
		}

		for key, value := range parameters {
			//Remove user-specified fields that we're handling
			if key == "fmt" || key == "q.page" {
				continue
			}
			queryUrl += fmt.Sprintf("&%s=%s", key, value)
		}
	} else {
		parameters = Query{"q.pageSize": "1000"}
	}
	s.queryUrl = queryUrl
	s.parameters = parameters
	s.currentPage = 0
	s.pageSize, _ = strconv.Atoi(parameters["q.pageSize"].(string))
	s.serverError = nil
	s.row = 0

	s.getPage(0)

	return s.maxRow, s.serverError

}

//-----------------------------------------------------------

/*
Iterate over each item in the query, handing the function a Data
for each item.

Example:
 rsn.Each(func(item api.Data) {
        fmt.Println(item.String("id"))
    })
*/
func (s *server) Each(each_func func(Data)) {
	for item := s.Next(); item != nil; item = s.Next() {
		each_func(item)
	}
}

//-----------------------------------------------------------

// Return the number of items in the query results
func (s *server) Count() int {
	return s.maxRow
}

//-----------------------------------------------------------

/*
Return a Data representing the next item in the results
Returns nil if we've seen all the items (this isn't very "go-like"
and should probably be changed to return err,data).
*/
func (s *server) Next() Data {
	page := s.row / s.pageSize
	if page != s.currentPage {
		s.currentPage = page
		s.getPage(page)
	}
	if s.row > s.maxRow || s.data == nil {
		return nil
	}
	if len(s.data) == 0 {
		return nil
	}
	retval := s.data[s.row%s.pageSize].(map[string]interface{})
	s.row++
	return retval
}

//-----------------------------------------------------------

type ServerWithPassword struct {
	server
	name, username, password, response string
}

//-----------------------------------------------------------

/*
Setup a connection to an IPsonar RSN with password authentication
*/
func NewServerWithPassword(name, username, password string) *ServerWithPassword {
	var server ServerWithPassword
	server.name, server.username, server.password = name, username, password

	//TODO query should return an error as appropriate
	server.query = func(request string) io.ReadCloser {
		// This is needed to deal with IPsonar's self-signed cert
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("GET", "https://"+name+"/"+request, nil)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		req.SetBasicAuth(username, password)
		resp, err := client.Do(req)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		return resp.Body
	}
	server.post = func(url, contentType string, outbuf *bytes.Buffer) (io.ReadCloser, error) {
		repoUrl := "https://" + name + "/" + url
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("POST", repoUrl, outbuf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		return resp.Body, nil
	}
	return &server
}

//-----------------------------------------------------------
type LocalServer struct {
	server
}

//-----------------------------------------------------------

// Setup a connection to the IPsonar RSN from the RSN itself
// (used for integrations hosted on the IPsonar RSN)
func NewLocalServer() *LocalServer {
	var server LocalServer

	//TODO query should return an error as appropriate
	server.query = func(request string) io.ReadCloser {
		resp, err := http.Get("http://127.0.0.1:8081/" + request)
		if err != nil {
			fmt.Println(err)
			return nil
		}
		return resp.Body
	}

	server.post = func(url, contentType string, outbuf *bytes.Buffer) (io.ReadCloser, error) {
		repoUrl := "http://127.0.0.1:8081/" + url
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("POST", repoUrl, outbuf)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", contentType)
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		return resp.Body, nil
	}
	return &server
}

//===========================================================
type Data map[string]interface{}
type Query map[string]interface{}

//-----------------------------------------------------------
// TODO return error if y would be nil
// TODO dump Data into the error so the user can figure out what was there

/*
Extract specific data from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) Interface(s ...string) interface{} {
	x := *data
	var y interface{}

	for _, i := range s {

		if _, ok := x[i]; ok == false {
			return nil
		}

		switch x[i].(type) {
		default:
			y = x[i].(interface{})

		case map[string]interface{}:
			x = x[i].(map[string]interface{})
		}
	}
	return y
}

//-----------------------------------------------------------

/*
Extract specific data cast to a String from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) String(s ...string) string {
	if data.Interface(s...) == nil {
		return ""
	}
	return data.Interface(s...).(string)
}

//-----------------------------------------------------------

/*
Extract specific data cast to a Bool from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) Bool(s ...string) bool {
	return data.Interface(s...).(bool)
}

//-----------------------------------------------------------

/*
Extract specific data cast to a Float from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) Float(s ...string) float64 {
	return data.Interface(s...).(float64)
}

//-----------------------------------------------------------

/*
Extract specific data cast to a Int from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) Int(s ...string) int {
	return int(data.Interface(s...).(float64))
}

//-----------------------------------------------------------

/*
Extract specific data cast to a Array from a particular result.
Pass in one or more strings to select a particular piece of
information.

Example:
ip := item.Interface("ip", "address")
*/
func (data *Data) Array(s ...string) []interface{} {
	return data.Interface(s...).([]interface{})
}

//TODO I'm not sure what happens if the resulting thing isn't
// an array.  If it isn't it should be coerced that way.

//=========================================================
// Functions / Types to implement WaitForReport
//=========================================================
type Report struct {
	Id        int
	Ipcount   int
	Name      string
	Tag       string
	Timestamp time.Time
	Title     string
}

// Helper type and functions to sort Reports

type Reports []*Report

func (s Reports) Len() int      { return len(s) }
func (s Reports) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

type ById struct{ Reports }
type ByIdDesc struct{ Reports }

func (s ByIdDesc) Less(i, j int) bool { return s.Reports[i].Id > s.Reports[j].Id }

//-----------------------------------------------------------
func (s *server) WaitForReport(d time.Duration) chan *Report {
	r := regexp.MustCompile(".*")
	c := s.WaitForReportRegexp(d, r)
	return c
}

//-----------------------------------------------------------
func (s *server) WaitForReportRegexp(d time.Duration, r *regexp.Regexp) chan *Report {
	reportChan := make(chan *Report, 10)
	var lastSeenReport int
	var maxReport int
	s2 := s.Copy()
	// Periodically poll the server writing reports to reportChan
	go func() {
		for {
			maxReport = 0
			_, _ = s2.Query("config.reports", Query{})
			s2.Each(func(item Data) {
				if item.Int("id") > lastSeenReport && r.MatchString(item.String("name")) {
					rx := regexp.MustCompile(`\@Date\((\d+)\)`)
					x, _ := strconv.Atoi(rx.FindStringSubmatch(item.String("timestamp"))[1])
					x64 := uint64(x)
					r := Report{
						Id:        item.Int("id"),
						Ipcount:   item.Int("ipcount"),
						Name:      item.String("name"),
						Tag:       item.String("tag"),
						Timestamp: time.Unix(int64(x64/1000), int64((x64%1000)*1000)),
						Title:     item.String("title"),
					}
					if r.Id > maxReport {
						maxReport = r.Id
					}
					reportChan <- &r
				}
			})
			lastSeenReport = maxReport
			time.Sleep(d)
		}
	}()
	return reportChan
}

//---------------------------------------------------------
func seenBaseDir() string {
	return "/u/integration/var"
}

//---------------------------------------------------------
func ProcessedReport(reportId int, intName string) bool {
	fileName := fmt.Sprintf("/report%d", reportId)
	_, err := os.Stat(seenBaseDir() + "/" + intName + fileName)
	if err == nil {
		return true
	} else {
		return false
	}
}

//---------------------------------------------------------
func MarkReportProcessed(reportId int, intName string) error {
	dirString := seenBaseDir() + "/" + intName
	_, err := os.Stat(dirString)
	if err != nil {
		if os.IsNotExist(err) {
			err := os.Mkdir(dirString, 0770)
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} // Directory present, create file
	file, err := os.Create(dirString + fmt.Sprintf("/report%d", reportId))
	if err != nil {
		return err
	}
	file.Close()
	return nil
}

//-----------------------------------------------------------
func (s *server) WriteReportAttributes(attributes []CustomAttribute, reportId string) error {
	outbuf := new(bytes.Buffer)

	if len(attributes) == 0 { // Return if nothing to write
		return nil
	}

	w := multipart.NewWriter(outbuf)

	label, err := w.CreateFormField("fmt")
	if err != nil {
		return err
	}
	label.Write([]byte("xml"))

	report, err := w.CreateFormField("p.reportId")
	if err != nil {
		return err
	}
	report.Write([]byte(reportId))

	pfile, err := w.CreateFormFile("p.attributeFile", "scratch")
	if err != nil {
		return err
	}
	pfile.Write(outbuf.Bytes())

	for _, v := range attributes {
		if len(v.Value) == 0 {
			continue
		}

		if len(v.Name) == 0 {
			return errors.New(fmt.Sprintf("Must have an attribute name (%v+)", v))
		}

		outbuf.WriteString(fmt.Sprintf("%s,%s,\"%s\"\n",
			v.CIDR, v.Name, v.Value))
	}

	w.Close()

	_, err = s.post("reporting/api/service/attribute.loadReportAttributes",
		w.FormDataContentType(), outbuf)

	if err != nil {
		return err
	}

	return nil
}

func (s *server) ClearReportAttributes(attributeName, reportId string) error {
	rsn := s.Copy()
	_, err := rsn.Query("attribute.removeAttributes", Query{
		"q.f.attribute.attributeType": attributeName,
		"q.f.report.id":               reportId})
	return err
}
