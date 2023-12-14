package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.AVDID != "AVD-ID100"
}

ignore {
    input.RuleID == "generic-wanted-rule"
}

ignore {
    input.Name == "GPL-3.0"
}
