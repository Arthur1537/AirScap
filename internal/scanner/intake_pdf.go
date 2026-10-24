package scanner

// Canonical intake PDFs contain only pages and RGB image streams. In particular
// they do not inherit FPDF's empty EmbeddedFiles catalog or duplicate resource
// keys for equal images. No OCR, annotations, scripts, forms or attachments.
import (
	"bytes"
	"compress/zlib"
	"fmt"
	"github.com/mzyy94/airscap/internal/vens"
	"image"
)

func GenerateIntakePDF(pages []vens.Page, dpi int) ([]byte, error) {
	if len(pages) == 0 || len(pages) > maxScanPages {
		return nil, fmt.Errorf("invalid page count")
	}
	if dpi <= 0 {
		dpi = 300
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, 3+3*len(pages))
	object := func(id int, data []byte) error {
		if out.Len()+len(data)+64 > maxScanBytes {
			return fmt.Errorf("intake PDF exceeds size limit")
		}
		offsets[id] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n", id)
		out.Write(data)
		out.WriteString("\nendobj\n")
		return nil
	}
	object(1, []byte("<< /Type /Catalog /Pages 2 0 R >>"))
	var kids bytes.Buffer
	for i := range pages {
		fmt.Fprintf(&kids, "%d 0 R ", 3+3*i)
	}
	object(2, []byte(fmt.Sprintf("<< /Type /Pages /Count %d /Kids [%s] >>", len(pages), kids.String())))
	for i, p := range pages {
		config, _, err := image.DecodeConfig(bytes.NewReader(p.JPEG))
		if err != nil || config.Width <= 0 || config.Height <= 0 || int64(config.Width)*int64(config.Height) > 40_000_000 {
			return nil, fmt.Errorf("invalid image page")
		}
		img, _, err := image.Decode(bytes.NewReader(p.JPEG))
		if err != nil {
			return nil, fmt.Errorf("incomplete image page")
		}
		d := dpi
		if embedded := detectImageDPI(p.JPEG); embedded > 0 {
			d = embedded
		} else if p.PixelSize != nil && p.PixelSize.XRes > 0 {
			d = int(p.PixelSize.XRes)
		}
		width, height := float64(config.Width)*72/float64(d), float64(config.Height)*72/float64(d)
		n := 3 + 3*i
		page := fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.6f %.6f] /Resources << /XObject << /Im0 %d 0 R >> >> /Contents %d 0 R >>", width, height, n+1, n+2)
		if err = object(n, []byte(page)); err != nil {
			return nil, err
		}
		var compressed bytes.Buffer
		z := zlib.NewWriter(&compressed)
		row := make([]byte, 3*config.Width)
		bounds := img.Bounds()
		for y := 0; y < config.Height; y++ {
			for x := 0; x < config.Width; x++ {
				r, g, b, a := img.At(bounds.Min.X+x, bounds.Min.Y+y).RGBA()
				// RGBA returns premultiplied channels; composite transparency onto white.
				row[3*x] = byte((r + 0xffff - a) >> 8)
				row[3*x+1] = byte((g + 0xffff - a) >> 8)
				row[3*x+2] = byte((b + 0xffff - a) >> 8)
			}
			if _, err = z.Write(row); err != nil {
				return nil, err
			}
			if out.Len()+compressed.Len() > maxScanBytes {
				return nil, fmt.Errorf("intake PDF exceeds size limit")
			}
		}
		if err = z.Close(); err != nil {
			return nil, err
		}
		var imageObject bytes.Buffer
		fmt.Fprintf(&imageObject, "<< /Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /FlateDecode /Length %d >>\nstream\n", config.Width, config.Height, compressed.Len())
		imageObject.Write(compressed.Bytes())
		imageObject.WriteString("\nendstream")
		if err = object(n+1, imageObject.Bytes()); err != nil {
			return nil, err
		}
		stream := fmt.Sprintf("q\n%.6f 0 0 %.6f 0 0 cm\n/Im0 Do\nQ\n", width, height)
		if err = object(n+2, []byte(fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(stream), stream))); err != nil {
			return nil, err
		}
	}
	start := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), start)
	if out.Len() > maxScanBytes {
		return nil, fmt.Errorf("intake PDF exceeds size limit")
	}
	return out.Bytes(), nil
}
