#' vulnpryr: A package for prying additional utility into your CVSS scores.
#'
#' @section vulnpryr functions:
#' The vulnpryer functions ...
#'
#' @docType package
#' @name vulnpryr
my_env <- new.env(parent = emptyenv())

#' Sample vulnerability attributes data
#'
#' A dataset of _dummy_ vulnerabilities attributes to demonstrate the 
#' functionality and use of vulnpryr. The variables are as follows:
#'
#' \itemize{
#' \item cve_id. CVE ID of the vulnerability
#' \item cvss_score. base CVSS  score (0 - 10)
#' \item msp. number of entries for the vulnerability in Metasploit (0+)
#' \item edb. number of entries for the vulnerability in Exploit DB (0+)
#' \item public_exploit. number of times the vulnerability has a known public vulnerability
#' \item private_exploit. number of times the vulnerability has a known private vulnerability
#' \item network_vector. number of times the vulnerability has a known network attack vector
#' \item impact_integrity. number of times the vulnerability has a known impact on integrity
#' \item impact_confidentiality. number of times the vulnerability has a known impact on confidentiality
#' }
#'
#' @docType data
#' @keywords vulndb
#' @name vulndb
#' @usage data(vulndb)
#' @format A data frame with 10 rows and 9 variables
NULL


#' Rescale vulnerabilities.
#' 
#' @param cve_id ID of the CVE in question
#' @param cvss_base The current CVSS rating of the vuln in question
#' @param avg_cvss_score Mean CVSS score of the population
#' @param msp_factor Amount to adjust CVSS if Metasploit module is present
#' @param edb_factor Amount to adjust CVSS if ExploitDB is present
#' @param private_exploit_factor Factor if private exploit exists
#' @param network_vector_factor Amount to adjust if not a network vuln
#' @param impact_factor Amount to adjust if impact is not confidentiality
#' @return Dataframe with the adjusted vuln
#' @examples
#' data(vulndb)
#' set_vulndb(vulndb)
#' vulnpryr("CVE-2013-2899", 5)
vulnpryr <- function(cve_id, cvss_base, avg_cvss_score = 6.2, 
                     msp_factor = 2.5, edb_factor = 1.5,
                     private_exploit_factor = .5, network_vector_factor = 2, 
                     impact_factor = 3) {

  vulndb <- get_vulndb()
  
  #cat(paste0("cve_id is ", cve_id))
  if (!any(vulndb$CVE_ID == cve_id)){
    #warning(paste0("Could not find ", cve_id))
    return(data.frame(modified = FALSE, cvss = cvss_base))
  }

  modified_score <- cvss_base + (cvss_base - avg_cvss_score) / avg_cvss_score
  if (sum(vulndb[vulndb$CVE_ID == cve_id, "msp"]) >= 1) {
    modified_score <- modified_score + msp_factor
  }

  # adjust up if exploit DB entry exists
  if (sum(vulndb[vulndb$CVE_ID == cve_id, "edb"]) >= 1) {
    modified_score <- modified_score + edb_factor
  }

  # adjust up if a private exploit is known
  if (sum(vulndb[vulndb$CVE_ID == cve_id, "private_exploit"]) >= 1) {
    modified_score <- modified_score + private_exploit_factor
  } else {
    modified_score <- modified_score - private_exploit_factor
  }

  # adjust down for impacts that aren't relevant to our loss scenario
  if ((sum(vulndb[vulndb$CVE_ID == cve_id, "impact_integrity"] ) < 1) &&
        (sum(vulndb[vulndb$CVE_ID == cve_id, "impact_confidentiality"]) < 1)) {
    modified_score  <-  modified_score - impact_factor
  }

  # adjust down for attack vectors that aren't in our loss scenario
  if (sum(vulndb[vulndb$CVE_ID == cve_id, "network_vector"]) < 1) {
    modified_score  <-  modified_score - network_vector_factor
  }

  # confirm that our modified score is within max/min limits
  if (modified_score > 10) {
    modified_score <- 10
  }
  if (modified_score < 0)  {
    modified_score <-  0
  }

  return(data.frame(modified = TRUE, cvss = modified_score))
}

#' Load the vulnerability attributes extract
#' @param vulndb_file Path to vulnerability attributes extract
load_vulndb <- function(vulndb_file) {
  
  if (file.exists(vulndb_file)) {
    set_vulndb(read.csv(vulndb_file, stringsAsFactors = FALSE))
  }
  
}

#' Get vulndb
#' @return The currently used vulnerability attributes DB
get_vulndb <- function() {
  my_env$vulndb
}

#' Set the vulnerability attributes database for use by vulnpryr
#' 
#' @param vulndb Dataframe of vulnerability attributes
set_vulndb <- function(vulndb) {
  my_env$vulndb <- vulndb
}
