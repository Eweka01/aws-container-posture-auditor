package report

import (
	"encoding/csv"
	"io"
	"strconv"
)

func RenderCSV(r *Report, w io.Writer) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{"check_id", "dimension", "severity", "resource", "region", "title", "description", "remediation"}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, f := range r.Findings {
		row := []string{
			f.CheckID,
			string(f.Dimension),
			string(f.Severity),
			f.Resource,
			f.Region,
			f.Title,
			f.Description,
			f.Remediation,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	// Summary row
	_ = cw.Write([]string{})
	_ = cw.Write([]string{"# Summary"})
	_ = cw.Write([]string{"overall_score", strconv.Itoa(r.Score.Overall)})
	_ = cw.Write([]string{"ops_score", strconv.Itoa(r.Score.OpsScore)})
	_ = cw.Write([]string{"supply_chain_score", strconv.Itoa(r.Score.SupplyChain)})
	_ = cw.Write([]string{"critical", strconv.Itoa(r.Score.Critical)})
	_ = cw.Write([]string{"high", strconv.Itoa(r.Score.High)})
	_ = cw.Write([]string{"medium", strconv.Itoa(r.Score.Medium)})
	_ = cw.Write([]string{"low", strconv.Itoa(r.Score.Low)})

	return cw.Error()
}
