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
 * Sophos SAVDI Scanner mock test class.
 *
 * @package    antivirus_savdi
 * @copyright  2020 Catalyst IT Australia
 * @author     Peter Burnett <peterburnett@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
namespace antivirus_savdi;

/**
 * Mockup class to use test_client instead of a regular client.
 *
 * @package    antivirus_savdi
 * @copyright  2020 Catalyst IT Australia
 * @author     Peter Burnett <peterburnett@catalyst-au.net>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class test_scanner extends \antivirus_savdi\scanner {
    /**
     * Gets a test client with correct fixture settings.
     *
     * @return test_client
     */
    public function get_client() {
        // Get file from SESSION var used to pass it.
        global $SESSION;
        $file = $SESSION->savdi_client_script;
        $client = new test_client();
        $client->connect('file', __DIR__ . '/../tests/fixtures/' . $file);
        return $client;
    }
}
