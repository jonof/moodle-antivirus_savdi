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
 * Tests for Sophos SAVDI antivirus client class.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

namespace antivirus_savdi\tests;
defined('MOODLE_INTERNAL') || die();

use antivirus_savdi\test_client;

/**
 * Tests for Sophos SAVDI antivirus client class.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class antivirus_savdi_client_testcase extends \advanced_testcase {
    public function test_connect_disconnect() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/connect-disconnect.txt');
        $client->disconnect();
    }

    public function test_scandata_without_support() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scandata-without-support.txt');

        $this->assertEquals(test_client::RESULT_ERROR_NOTSUPPORTED, $client->scandata('data'));
    }

    public function test_scandata_too_large() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scandata-too-large.txt');

        $this->assertEquals(test_client::RESULT_ERROR_TOOLARGE, $client->scandata('data'));
    }

    public function test_scandata_clean() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scandata-clean.txt');

        $this->assertEquals(test_client::RESULT_OK, $client->scandata('data'));
        $this->assertEquals([], $client->get_scan_viruses());
        $this->assertEquals(test_client::SAVI_OK, $client->get_scan_code());
    }

    public function test_scandata_infected() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scandata-infected.txt');

        $this->assertEquals(test_client::RESULT_VIRUS, $client->scandata('data'));
        $this->assertEquals(['' => 'EICAR-AV-Test'], $client->get_scan_viruses());
        $this->assertEquals(test_client::SAVI_ERROR_VIRUSPRESENT, $client->get_scan_code());
        $this->assertDebuggingCalled();
    }

    public function test_scandata_timeout() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scandata-timeout.txt');

        $this->assertEquals(test_client::RESULT_ERROR, $client->scandata('data'));
        $this->assertEquals(test_client::SAVI_ERROR_SCANTIMEOUT, $client->get_scan_code());
        $this->assertDebuggingCalled();
    }

    public function test_scanfile_without_support() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scanfile-without-support.txt');

        $this->assertEquals(test_client::RESULT_ERROR_NOTSUPPORTED, $client->scanfile('/path'));
    }

    public function test_scanfile_clean() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scanfile-clean.txt');

        $this->assertEquals(test_client::RESULT_OK, $client->scanfile('/path'));
        $this->assertEquals([], $client->get_scan_viruses());
        $this->assertEquals(test_client::SAVI_OK, $client->get_scan_code());
    }

    public function test_scanfile_infected() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scanfile-infected.txt');

        $this->assertEquals(test_client::RESULT_VIRUS, $client->scanfile('/path'));
        $this->assertEquals(['/path' => 'EICAR-AV-Test'], $client->get_scan_viruses());
        $this->assertEquals(test_client::SAVI_ERROR_VIRUSPRESENT, $client->get_scan_code());
        $this->assertDebuggingCalled();
    }

    public function test_scanfile_timeout() {
        $client = new test_client();
        $client->connect('file', __DIR__ . '/fixtures/scanfile-timeout.txt');

        $this->assertEquals(test_client::RESULT_ERROR, $client->scanfile('/path'));
        $this->assertEquals(test_client::SAVI_ERROR_SCANTIMEOUT, $client->get_scan_code());
        $this->assertDebuggingCalled();
    }

    public function test_connect_retries_exceeded() {
        $client = new test_client();
        $client->opensocketfails = 2;

        $this->expectException(\moodle_exception::class);
        $this->expectExceptionMessage('antivirus_savdi/errorcantopenfilesocket');
        $client->connect('file', __DIR__ . '/fixtures/connect-disconnect.txt', 1);
    }

    public function test_connect_retries_sufficient() {
        $client = new test_client();
        $client->opensocketfails = 1;

        $client->connect('file', __DIR__ . '/fixtures/connect-disconnect.txt', 1);
    }
}
