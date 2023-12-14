package trivy

import data.lib.trivy

default ignore=false

ignore {
	input.AVDID != "AVD-TEST-0001"
}

ignore {
    input.RuleID == "generic-wanted-rule"
}

ignore {
    input.Name == "GPL-3.0"
}
