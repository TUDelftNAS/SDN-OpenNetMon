# #Copyright (C) 2013, Delft University of Technology, Faculty of Electrical Engineering, Mathematics and Computer Science, Network Architectures and Services, Niels van Adrichem
#
# This file is part of OpenNetMon.
#
# OpenNetMon is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# OpenNetMon is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with OpenNetMon.  If not, see <http://www.gnu.org/licenses/>.

# Special thanks go to James McCauley and all people connected to the POX project, without their work and provided samples OpenNetMon could not have been created in the way it is now.
from datetime import datetime

def launch (postfix=datetime.now().strftime("%Y%m%d%H%M%S")):
        from log.level import launch
        launch(DEBUG=True)

        from samples.pretty_log import launch
        launch()

        from openflow.keepalive import launch
        launch(interval=15) # 15 seconds

        from openflow.discovery import launch
        launch()

        #we solved the flooding-problem in l2_multi_withstate
        #from openflow.spanning_tree import launch
        #launch(no_flood = True, hold_down = True)

        from opennetmon.forwarding import launch
        launch(l3_matching=False)

        from opennetmon.monitoring import launch
        launch(postfix=postfix)
