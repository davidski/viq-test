library(vulnpryr)

context("CVSS rescore")

data(vulndb)
set_vulndb(vulndb)

test_that("vulnpryr is number of characters", {
  expect_is(vulnpryr("CVE-2015-001", 10), "data.frame")
})
