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
 * Sophos SAVDI admin settings.
 *
 * @package    antivirus_savdi
 * @copyright  2020 The University of Southern Queensland
 * @author     Jonathon Fowler <fowlerj@usq.edu.au>
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

if ($ADMIN->fulltree) {
    $options = array(
        'unix' => new lang_string('conntypeunix', 'antivirus_savdi'),
        'tcp'  => new lang_string('conntypetcp', 'antivirus_savdi'),
    );
    $settings->add(new admin_setting_configselect('antivirus_savdi/conntype',
            new lang_string('conntype', 'antivirus_savdi'),
            new lang_string('conntypedescr', 'antivirus_savdi'), 'unix', $options));

    $settings->add(new admin_setting_configtext('antivirus_savdi/conntcp',
            new lang_string('conntcp', 'antivirus_savdi'),
            null, 'localhost:4010', PARAM_RAW_TRIMMED));
    $settings->add(new admin_setting_configtext('antivirus_savdi/connunix',
            new lang_string('connunix', 'antivirus_savdi'),
            null, '/var/run/savdi.sock', PARAM_RAW_TRIMMED));
    $settings->add(new admin_setting_configcheckbox('antivirus_savdi/scannerisremote',
            new lang_string('scannerisremote', 'antivirus_savdi'),
            new lang_string('scannerisremotedescr', 'antivirus_savdi'),
            0));
    $settings->add(new admin_setting_configcheckbox('antivirus_savdi/chmodscanfile',
            new lang_string('chmodscanfile', 'antivirus_savdi'),
            new lang_string('chmodscanfiledescr', 'antivirus_savdi'),
            1));

    $options = array(
        'donothing' => new lang_string('daemonerrordonothing', 'antivirus_savdi'),
        'actlikevirus' => new lang_string('daemonerroractlikevirus', 'antivirus_savdi'),
    );
    $settings->add(new admin_setting_configselect('antivirus_savdi/ondaemonerror',
            new lang_string('ondaemonerror', 'antivirus_savdi'),
            new lang_string('ondaemonerrordescr', 'antivirus_savdi'), 'donothing', $options));
}
