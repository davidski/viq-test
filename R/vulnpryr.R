#' vulnpryr: A package for prying additional utility into your CVSS scores.
#'
#' @section vulnpryr functions:
#' The vulnpryer functions ...
#'
#' @docType package
#' @name vulnpryr
my_env <- new.env(parent = emptyenv())

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

#' Load VulnDB extract
#' @param vulndb_file Path to VulnDB extract
load_vulndb <- function(vulndb_file) {
  
  if (file.exists(vulndb_file)) {
    my_env$vulndb <- read.csv(vulndb_file, stringsAsFactors = FALSE)
  }
  
}

#' Get vulndb
get_vulndb <- function() {
  my_env$vulndb
}
