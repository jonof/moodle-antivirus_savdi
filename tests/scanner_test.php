<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Sophos SAVDI Scanner test class.
 *
 * @package    antivirus_savdi
 * @copyright  2020 Catalyst IT Australia
 * @author     Peter Burnett <peterburnett@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi;

use antivirus_savdi\test_scanner;

/**
 * Tests for Sophos SAVDI antivirus scanner class.
 *
 * @package    antivirus_savdi
 * @copyright  2020 Catalyst IT Australia
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @covers     \antivirus_savdi\scanner
 */
final class scanner_test extends \advanced_testcase {
    public function test_is_configured(): void {
        $this->resetAfterTest(true);

        // Test when no config selected.
        set_config('conntype', '', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertFalse($scanner->is_configured());

        // Test when type is selected, but no config is entered.
        set_config('conntype', 'unix', 'antivirus_savdi');
        set_config('connunix', '', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertFalse($scanner->is_configured());

        set_config('conntype', 'tcp', 'antivirus_savdi');
        set_config('conntcp', '', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertFalse($scanner->is_configured());

        // Test TCP with remote and local IPs.
        set_config('conntcp', '123.123.123.123:4010', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertTrue($scanner->is_configured());

        set_config('conntcp', '127.0.0.1:4010', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertTrue($scanner->is_configured());

        // Test unix with correct settings.
        set_config('conntype', 'unix', 'antivirus_savdi');
        set_config('connunix', '/var/run/savdi.sock', 'antivirus_savdi');
        $scanner = new \antivirus_savdi\scanner();
        $this->assertTrue($scanner->is_configured());
    }

    public function test_scan_file(): void {
        $this->resetAfterTest(true);
        global $SESSION;

        // Let scanner daemon errors pass normally.
        set_config('ondaemonerror', 'donothing', 'antivirus_savdi');

        // Unable to tests fileperms, using dummy data + client.
        set_config('chmodscanfile', 0, 'antivirus_savdi');
        $scanner = new test_scanner();

        // Scan a file, and verify no exception thrown.
        // Can pass any filepath, will be ignored by the test client.
        $SESSION->savdi_client_script = 'scanfile-clean.txt';
        $this->assertEquals($scanner::SCAN_RESULT_OK, $scanner->scan_file('/path', '/path'));

        // Now change the test script to a virus found script.
        $SESSION->savdi_client_script = 'scanfile-infected.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_file('/path', '/path'));
        $this->assertDebuggingCalled();

        // Now test that a daemon failure doesn't cause an error by default.
        $SESSION->savdi_client_script = 'scanfile-timeout.txt';
        $this->assertEquals($scanner::SCAN_RESULT_ERROR, $scanner->scan_file('/path', '/path'));
        $this->assertDebuggingCalled();

        // Test that not supported files error.
        $SESSION->savdi_client_script = 'scanfile-without-support.txt';
        $this->assertEquals($scanner::SCAN_RESULT_ERROR, $scanner->scan_file('/path', '/path'));

        // Check virus response when config is set to behave like so on error.
        set_config('ondaemonerror', 'actlikevirus', 'antivirus_savdi');
        $scanner = new test_scanner();

        $SESSION->savdi_client_script = 'scanfile-timeout.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_file('/path', '/path'));
        $this->assertDebuggingCalled();

        // Test that not supported files error.
        $SESSION->savdi_client_script = 'scanfile-without-support.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_file('/path', '/path'));
    }

    public function test_scan_data(): void {
        $this->resetAfterTest(true);
        global $SESSION;

        // Let scanner daemon errors pass normally.
        set_config('ondaemonerror', 'donothing', 'antivirus_savdi');

        $scanner = new test_scanner();

        // Clean.
        $SESSION->savdi_client_script = 'scandata-clean.txt';
        $this->assertEquals($scanner::SCAN_RESULT_OK, $scanner->scan_data('data'));

        // Infected.
        $SESSION->savdi_client_script = 'scandata-infected.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_data('data'));
        $this->assertDebuggingCalled();

        // Test various errors with scandata return OK.
        $SESSION->savdi_client_script = 'scandata-timeout.txt';
        $this->assertEquals($scanner::SCAN_RESULT_ERROR, $scanner->scan_data('data'));
        $this->assertDebuggingCalled();

        $SESSION->savdi_client_script = 'scandata-too-large.txt';
        $this->assertEquals($scanner::SCAN_RESULT_ERROR, $scanner->scan_data('data'));

        $SESSION->savdi_client_script = 'scandata-without-support.txt';
        $this->assertEquals($scanner::SCAN_RESULT_ERROR, $scanner->scan_data('data'));

        // Check virus response when config is set to behave like so on error.
        set_config('ondaemonerror', 'actlikevirus', 'antivirus_savdi');
        $scanner = new test_scanner();

        // Test various failures with scandata return errors.
        $SESSION->savdi_client_script = 'scandata-timeout.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_data('data'));
        $this->assertDebuggingCalled();

        $SESSION->savdi_client_script = 'scandata-too-large.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_data('data'));

        $SESSION->savdi_client_script = 'scandata-without-support.txt';
        $this->assertEquals($scanner::SCAN_RESULT_FOUND, $scanner->scan_data('data'));
    }
}
