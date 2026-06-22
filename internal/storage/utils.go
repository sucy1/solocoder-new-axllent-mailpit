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

	// Apply Chinese ngram tokenization for better Chinese search
	return chineseNgramTokenize(rawText)
}

// chineseNgramTokenize performs unigram + bigram tokenization on Chinese characters
// to support both single-char and multi-char Chinese searches.
// Non-Chinese text is left as-is.
// E.g., "你好世界" becomes "你 好 世 界 你好 好世 世界"
func chineseNgramTokenize(s string) string {
	var result strings.Builder
	var chineseBuf strings.Builder

	flushChinese := func() {
		chinese := chineseBuf.String()
		chineseBuf.Reset()
		runes := []rune(chinese)

		// Add unigrams (single chars) for single-char search support
		for _, r := range runes {
			result.WriteRune(r)
			result.WriteRune(' ')
		}

		// Add bigrams for multi-char search accuracy
		if len(runes) > 1 {
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

// chineseSearchTokenize tokenizes a Chinese search term appropriately.
// - Single char: return as-is (matches unigram)
// - Multiple chars: convert to bigrams for exact phrase matching
func chineseSearchTokenize(s string) string {
	// First clean the input
	s = cleanString(s)

	var hasChinese bool
	for _, r := range s {
		if isChineseChar(r) {
			hasChinese = true
			break
		}
	}

	// No Chinese, return as-is
	if !hasChinese {
		return s
	}

	// Extract only Chinese runes to determine length
	var chineseRunes []rune
	for _, r := range s {
		if isChineseChar(r) {
			chineseRunes = append(chineseRunes, r)
		}
	}

	// Single Chinese char: return as-is for unigram matching
	if len(chineseRunes) == 1 {
		return string(chineseRunes)
	}

	// Multiple Chinese chars: use ngram tokenization (uni + bi)
	return chineseNgramTokenize(s)
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
