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
 * Sophos SAVDI antivirus callbacks and interfaces.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

/**
 * Declare Check API status checks we implement.
 *
 * @return array of core\check\check instances
 */
function antivirus_savdi_status_checks() {
    // Don't return any checks if the plugin isn't enabled.
    $enabledavs = core_plugin_manager::instance()->get_enabled_plugins('antivirus');
    if (!in_array('savdi', $enabledavs)) {
        return [];
    }

    return [
        new antivirus_savdi\check\connectivity(),
    ];
}
