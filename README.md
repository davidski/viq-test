viq-test
=========
<!-- badges: start -->
[![R build status](https://github.com/davidski/viq-test/workflows/R-CMD-check/badge.svg)](https://github.com/davidski/viq-test/actions)
[![Coverage Status](https://coveralls.io/repos/davidski/viq-test/badge.svg?branch=master)](https://coveralls.io/r/davidski/viq-test?branch=master)
<!-- badges: end -->


VIQ-Test is an R based toolset for performing analysis on vulnerability prioritization schemes.

#Installation
`
devtools:github("davidski\viq-test")
`

#Usage

```
library(viq-test)

#Load vulnerability fact table
vulndb_file <- ".\vulnerability_facts.csv"
vulnpryr::load_vulndb(vulndb_file)

#Rescore a vulnerability
vulnpryer(cve_id = "CVE-2014-0013", cvss_base = 5)
```

Weightings can be overridden by specifying manual values in the function call.

`
vulnpryer(cve_id = "CVE-2014-0013", cvss_base = 5, msp_factor = 2, network_vector_factor = 3)
`

#Acknowledgements
VIQ-Test is patterned after the [TIQ-Test](https://github.com/mlsecproject/tiq-test) project from 
the [MLSec Project](https://mlsecproject.org)
