package parseFile

import (
	"bufio"
	"fmt"
	"golang.org/x/exp/slices"
	"os"
	"testing"
)

func Test_parseTarget(t *testing.T) {

	err := test_case("testcase/test1.txt", "testcase/test1_results.txt")
	if err != nil {
		t.Error(err)
		return
	}

}

func test_case(file1 string, file2 string) error {

	file1_results, err := ParseTagetsFromFile(file1)
	if err != nil {
		return err
	}

	file2_contents, err := readFile(file2)
	if err != nil {
		return err
	}

	//Same line count check
	if len(file1_results) != len(file2_contents) {
		return fmt.Errorf("line count does not match. File 1: %d, File 2: %d", len(file1_results), len(file2_contents))
	}

	//Compare entries
	err = compare_entries(file1_results, file2_contents)
	if err != nil {
		return err
	}

	return nil

}

func compare_entries(file1_contents []string, file2_contents []string) error {
	file2_entrycount := len(file2_contents)
	file1_entrycount := 0

	for _, entry := range file1_contents {
		if slices.Contains(file2_contents, entry) {
			file1_entrycount++
		} else {
			return fmt.Errorf("unexpected entry found: %s", entry)
		}
	}

	if file2_entrycount == file1_entrycount {
		return nil
	}

	for _, entry2 := range file2_contents {
		if slices.Contains(file1_contents, entry2) {
			continue
		}
		return fmt.Errorf("entry not found in results: %s", entry2)
	}
	return nil

}

func readFile(filepath string) ([]string, error) {
	readfile, err := os.Open(filepath)
	if err != nil {
		return []string{}, err
	}

	//Serperate file by lines
	fileScanner := bufio.NewScanner(readfile)
	fileScanner.Split(bufio.ScanLines)

	var lines []string
	for fileScanner.Scan() {
		lines = append(lines, fileScanner.Text())
	}

	return lines, nil
}
