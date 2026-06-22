package storage

import (
	"net/mail"
	"os"
	"regexp"
	"strings"
	"sync"

	"github.com/axllent/mailpit/internal/html2text"
	"github.com/axllent/mailpit/internal/logger"
	"github.com/axllent/mailpit/internal/tools"
	"github.com/jhillyerd/enmime/v2"
)

var (
	// for stats to prevent import cycle
	mu sync.RWMutex
	// StatsDeleted for counting the number of messages deleted
	StatsDeleted uint64
)

// AddTempFile adds a file to the slice of files to delete on exit
func AddTempFile(s string) {
	temporaryFiles = append(temporaryFiles, s)
}

// DeleteTempFiles will delete files added via AddTempFiles
func deleteTempFiles() {
	for _, f := range temporaryFiles {
		if err := os.Remove(f); err == nil {
			logger.Log().Debugf("removed temporary file: %s", f)
		}
	}
}

// Return a header field as a []*mail.Address, or "null" is not found/empty
func addressToSlice(env *enmime.Envelope, key string) []*mail.Address {
	data, err := env.AddressList(key)
	if err != nil || data == nil {
		return []*mail.Address{}
	}

	return data
}

// Generate the search text based on some header fields (to, from, subject etc)
// and either the stripped HTML body (if exists) or text body
func createSearchText(env *enmime.Envelope) string {
	var b strings.Builder

	_, _ = b.WriteString(env.GetHeader("From") + " ")
	_, _ = b.WriteString(env.GetHeader("Subject") + " ")
	_, _ = b.WriteString(env.GetHeader("To") + " ")
	_, _ = b.WriteString(env.GetHeader("Cc") + " ")
	_, _ = b.WriteString(env.GetHeader("Bcc") + " ")
	_, _ = b.WriteString(env.GetHeader("Reply-To") + " ")
	_, _ = b.WriteString(env.GetHeader("Return-Path") + " ")

	h, _ := html2text.Strip(env.HTML, true)
	if h != "" {
		_, _ = b.WriteString(h + " ")
	} else {
		_, _ = b.WriteString(env.Text + " ")
	}
	// add attachment filenames
	for _, a := range env.Attachments {
		_, _ = b.WriteString(a.FileName + " ")
	}

	rawText := cleanString(b.String())

	// Apply Chinese bigram tokenization for better Chinese search
	return chineseBigramTokenize(rawText)
}

// chineseBigramTokenize performs bigram (2-character) tokenization on Chinese characters
// to improve Chinese search accuracy. Non-Chinese text is left as-is.
// E.g., "你好世界" becomes "你好 好世 世界"
func chineseBigramTokenize(s string) string {
	var result strings.Builder
	var chineseBuf strings.Builder

	flushChinese := func() {
		chinese := chineseBuf.String()
		chineseBuf.Reset()
		runes := []rune(chinese)
		if len(runes) == 1 {
			result.WriteRune(runes[0])
			result.WriteRune(' ')
		} else if len(runes) > 1 {
			for i := 0; i < len(runes)-1; i++ {
				result.WriteRune(runes[i])
				result.WriteRune(runes[i+1])
				result.WriteRune(' ')
			}
		}
	}

	for _, r := range s {
		if isChineseChar(r) {
			chineseBuf.WriteRune(r)
		} else {
			if chineseBuf.Len() > 0 {
				flushChinese()
			}
			result.WriteRune(r)
		}
	}

	if chineseBuf.Len() > 0 {
		flushChinese()
	}

	return strings.TrimSpace(result.String())
}

// isChineseChar checks if a rune is a Chinese character (CJK Unified Ideographs)
func isChineseChar(r rune) bool {
	return (r >= '\u4e00' && r <= '\u9fff') || // CJK Unified Ideographs
		(r >= '\u3400' && r <= '\u4dbf') || // CJK Unified Ideographs Extension A
		(r >= 0x20000 && r <= 0x2a6df) // CJK Unified Ideographs Extension B
}

// CleanString removes unwanted characters from stored search text and search queries
func cleanString(str string) string {
	// replace \uFEFF with space, see https://github.com/golang/go/issues/42274#issuecomment-1017258184
	str = strings.ReplaceAll(str, string('\uFEFF'), " ")

	// remove/replace new lines
	re := regexp.MustCompile(`(\r?\n|\t|>|<|"|\,|;|\(|\))`)
	str = re.ReplaceAllString(str, " ")

	// remove duplicate whitespace and trim
	return strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(str)), " "))
}

// LogMessagesDeleted logs the number of messages deleted
func logMessagesDeleted(n int) {
	mu.Lock()
	StatsDeleted = StatsDeleted + tools.SafeUint64(n)
	mu.Unlock()
}

// IsFile returns whether a path is a file
func isFile(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) || !info.Mode().IsRegular() {
		return false
	}

	return true
}

// Convert `%` to `%%` for SQL searches
func escPercentChar(s string) string {
	return strings.ReplaceAll(s, "%", "%%")
}
