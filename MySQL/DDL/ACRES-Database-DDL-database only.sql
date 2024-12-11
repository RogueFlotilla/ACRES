/*****************************************************************************************/
/*           A.I.-enhanced Cyber Resiliency Evaluation System (ACRES) Database           */
/*****************************************************************************************/
/*                                                                                       */
/* Kristian Alleyne, Richard Flores, Claire Kamobaya, Matthew Penn                       */
/* Dr. Xiang Liu                                                                         */
/* IT 310 A - Database Technology                                                        */
/* December 10, 2024                                                                     */
/*                                                                                       */
/*****************************************************************************************/
/*                                     CREATE SCHEMA                                     */
/*****************************************************************************************/
CREATE SCHEMA acres;

/*****************************************************************************************/
/*                                     SELECT SCHEMA                                     */
/*****************************************************************************************/
USE acres;

/*****************************************************************************************/
/*                                     CREATE TABLES                                     */
/*****************************************************************************************/
CREATE TABLE APT_GROUPS(
    apt_group                       VARCHAR(25)                    NOT NULL,
    alias_names                     VARCHAR(100)                   NULL,
    description                     VARCHAR(5000)                  NOT NULL,
    CONSTRAINT                      APT_GROUPS_PK                  PRIMARY KEY(apt_group)
    );

CREATE TABLE CRITICALITY_DEFINITIONS(
    criticality_value               INT                            NOT NULL,
    criticality_name                VARCHAR(25)                    NOT NULL,
    downtime_allowed                VARCHAR(25)                    NOT NULL,
    CONSTRAINT                      CRITICALITY_DEFINITIONS_PK
                                        PRIMARY KEY(criticality_value)
    );

CREATE TABLE VULNERABILITIES_DATA(
    cve_number                      VARCHAR(14)                    NOT NULL,
    nvd_score                       DECIMAL(2, 1)                  NOT NULL,
    cvss_version                    CHAR(3)                        NOT NULL,
    vector_string                   VARCHAR(44)                    NOT NULL,
    attack_vector                   VARCHAR(16)                    NOT NULL,
    attack_complexity               VARCHAR(6)                     NOT NULL,
    privilege_required              VARCHAR(8)                     NULL,
    user_interaction_required       VARCHAR(8)                     NOT NULL,
    scope_changed                   VARCHAR(9)                     NULL,
    impact_confidentiality          VARCHAR(8)                     NOT NULL,
    impact_integrity                VARCHAR(8)                     NOT NULL,
    impact_availability             VARCHAR(8)                     NOT NULL,
    base_score                      DECIMAL(2, 1)                  NOT NULL,
    base_severity                   VARCHAR(14)                    NOT NULL,
    exploitability_score            DECIMAL(3, 1)                  NOT NULL,
    impact_score                    DECIMAL(3, 1)                  NOT NULL,
    description                     VARCHAR(5000)                  NOT NULL,
    CONSTRAINT                      VULNERABILITIES_DATA_PK        PRIMARY KEY(cve_number),
    CONSTRAINT                      VULNERABILITIES_DATA_cve_number
                                        CHECK (cve_number LIKE 'CVE-____-____%'
                                        AND LENGTH(cve_number) BETWEEN 13 AND 14),
    CONSTRAINT                      VULNERABILITIES_DATA_cvss_version
                                        CHECK (cvss_version IN('2.0', '3.0', '3.1', '4.0')),
    CONSTRAINT                      VULNERABILITIES_DATA_attack_vector
                                        CHECK (attack_vector IN(
                                            'PHYSICAL', 'LOCAL', 'ADJACENT_NETWORK', 
                                            'NETWORK')),
    CONSTRAINT                      VULNERABILITIES_DATA_attack_complexity
                                        CHECK (attack_complexity IN(
                                            'LOW', 'MEDIUM', 'HIGH')),
    CONSTRAINT                      VULNERABILITIES_DATA_privilege_required
                                        CHECK (privilege_required IN(
                                            null, 'NONE', 'LOW', 'HIGH')),
    CONSTRAINT                      VULNERABILITIES_DATA_user_interaction_required
                                        CHECK (user_interaction_required IN(
                                            'NONE', 'REQUIRED', True, False)),
    CONSTRAINT                      VULNERABILITIES_DATA_scope_changed
                                        CHECK (privilege_required IN(
                                            null, 'UNCHANGED', 'CHANGED')),
    CONSTRAINT                      VULNERABILITIES_DATA_impact_confidentiality
                                        CHECK (impact_confidentiality IN(
                                            'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
    CONSTRAINT                      VULNERABILITIES_DATA_impact_integrity
                                        CHECK (impact_integrity IN(
                                            'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
    CONSTRAINT                      VULNERABILITIES_DATA_impact_availability
                                        CHECK (impact_availability IN(
                                            'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
    CONSTRAINT                      VULNERABILITIES_DATA_base_score
                                        CHECK (base_score >= 0.00 AND base_score <= 10.00),
    CONSTRAINT                      VULNERABILITIES_DATA_base_severity
                                        CHECK (base_severity IN(
                                            'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT                      VULNERABILITIES_DATA_exploitability_score
                                        CHECK (exploitability_score >= 0.00
                                        AND exploitability_score <= 10.00),
    CONSTRAINT                      VULNERABILITIES_DATA_impact_score
                                        CHECK (impact_score >= 0.00 AND impact_score <= 10)
    );

CREATE TABLE INFRASTRUCTURE_CATEGORIES(
    category_id                     INT                            NOT NULL AUTO_INCREMENT,
    category_name                   VARCHAR(100)                   NOT NULL,
    CONSTRAINT                      INFRASTRUCTURE_CATEGORIES_PK   PRIMARY KEY(category_id)
    );

CREATE TABLE HARDWARE(
    hardware_id                     INT                            NOT NULL AUTO_INCREMENT,
    infra_make                      VARCHAR(25)                    NOT NULL,
    infra_model                     VARCHAR(25)                    NOT NULL,
    description                     VARCHAR(5000)                  NULL,
    category_id                     INT                            NOT NULL,
    CONSTRAINT                      HARDWARE_PK                    PRIMARY KEY(hardware_id),
    CONSTRAINT                      SYSTEM_SCORING_IN_FK           FOREIGN KEY(category_id)
                                        REFERENCES INFRASTRUCTURE_CATEGORIES(category_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      HARDWARE
                                        UNIQUE(infra_make, infra_model)
    );
    
CREATE TABLE ENDPOINT_NODES(
    endpoint_id                     INT                            NOT NULL AUTO_INCREMENT,
    endpoint_name                   VARCHAR(100)                   NOT NULL,
    CONSTRAINT                      HARDWARE_PK                    PRIMARY KEY(endpoint_id),
    CONSTRAINT                      ENDPOINT_NODES                 UNIQUE(endpoint_name)
    );

CREATE TABLE HARDWARE_MAPPING(
    hardware_id                     INT                            NOT NULL,
    serial_number                   VARCHAR(25)                    NOT NULL,
    category_id                     INT                            NOT NULL,
    endpoint_id                     INT                            NOT NULL,
    CONSTRAINT                      HARDWARE_MAPPING_PK
                                        PRIMARY KEY(hardware_id, serial_number),
    CONSTRAINT                      HARDWARE_MAPPING_H_FK          FOREIGN KEY(hardware_id)
                                        REFERENCES HARDWARE(hardware_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      HARDWARE_MAPPING_IC_FK         FOREIGN KEY(category_id)
                                        REFERENCES INFRASTRUCTURE_CATEGORIES(category_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      HARDWARE_MAPPING_EN_FK         FOREIGN KEY(endpoint_id)
                                        REFERENCES ENDPOINT_NODES(endpoint_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      FILTER_REPEATS_HM
                                        UNIQUE(hardware_id, serial_number)
);
    
CREATE TABLE SOFTWARE_FIRMWARE(
    software_id                     INT                            NOT NULL AUTO_INCREMENT,
    software_make                   VARCHAR(50)                    NOT NULL,
    software_name                   VARCHAR(100)                   NOT NULL,
    software_version                VARCHAR(25)                    NOT NULL,
    CONSTRAINT                      SOFTWARE_FIRMWARE_PK           PRIMARY KEY(software_id),
    CONSTRAINT                      FILTER_REPEATS_SF
                                        UNIQUE(
                                            software_make, software_name, software_version)
    );
    
CREATE TABLE SYSTEM_SCORING(
    apt_group                       VARCHAR(25)                    NOT NULL,
    score_name                      VARCHAR(9)                     NOT NULL,
    score                           DECIMAL(3, 2)                  NOT NULL,
    reasoning                       VARCHAR(5000)                  NULL,
    remediations                    JSON                           NULL,
    CONSTRAINT                      SYSTEM_SCORING_PK
                                        PRIMARY KEY(apt_group, score_name),
    CONSTRAINT                      SYSTEM_SCORING_AG_FK           FOREIGN KEY(apt_group)
                                        REFERENCES APT_GROUPS(apt_group)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      SYSTEM_SCORING_score_name
                                        CHECK (score_name IN(
                                            'Physical', 'Personnel', 'Policies')),
    CONSTRAINT                      SYSTEM_SCORING_score
                                        CHECK (score >= 0.0 AND score <= 1.00)
    );

CREATE TABLE FUNCTION_DEFINITIONS(
    function_number                 VARCHAR(4)                     NOT NULL,
    function_name                   VARCHAR(100)                   NOT NULL,
    work_area                       CHAR(100)                      NOT NULL,
    criticality_value               INT                            NOT NULL,
    CONSTRAINT                      FUNCTION_DEFINITIONS_PK
                                        PRIMARY KEY(function_number),
    CONSTRAINT                      FUNCTION_DEFINITIONS_CD_FK
                                        FOREIGN KEY(criticality_value)
                                            REFERENCES
                                                CRITICALITY_DEFINITIONS(criticality_value)
                                                    ON UPDATE CASCADE
                                                    ON DELETE NO ACTION
    );

CREATE TABLE FUNCTION_MAPPING(
    endpoint_id                     INT                            NOT NULL,
    function_number                 VARCHAR(4)                     NOT NULL,
    CONSTRAINT                      FUNCTION_MAPPING_PK
                                        PRIMARY KEY(endpoint_id, function_number),
    CONSTRAINT                      FUNCTION_MAPPING_IN_FK         FOREIGN KEY(endpoint_id)
                                        REFERENCES ENDPOINT_NODES(endpoint_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      FUNCTION_MAPPING_FD_FK
                                        FOREIGN KEY(function_number)
                                            REFERENCES FUNCTION_DEFINITIONS(function_number)
                                                ON UPDATE CASCADE
                                                ON DELETE NO ACTION
    );
    
CREATE TABLE SOFTWARE_FIRMWARE_MAPPING(
    endpoint_id                     INT                            NOT NULL,
    software_id                     INT                            NOT NULL,
    CONSTRAINT                      SOFTWARE_FIRMWARE_MAPPING_PK
                                        PRIMARY KEY(endpoint_id, software_id),
    CONSTRAINT                      SOFTWARE_FIRMWARE_MAPPING_EN_FK FOREIGN KEY(endpoint_id)
                                    REFERENCES ENDPOINT_NODES(endpoint_id)
                                        ON UPDATE CASCADE
                                        ON DELETE NO ACTION,
    CONSTRAINT                      SOFTWARE_FIRMWARE_MAPPING_SF_FK FOREIGN KEY(software_id)
                                    REFERENCES SOFTWARE_FIRMWARE(software_id)
                                        ON UPDATE CASCADE
                                        ON DELETE NO ACTION
    );
    
CREATE TABLE VULNERABILITY_INSTANCES(
    cve_number                      VARCHAR(14)                    NOT NULL,
    software_id                     INT                            NOT NULL,
    CONSTRAINT                      VULNERABILITY_INSTANCES_PK
                                        PRIMARY KEY(cve_number, software_id),
    CONSTRAINT                      VULNERABILITY_INSTANCES_DV_FK  FOREIGN KEY(cve_number)
                                    REFERENCES VULNERABILITIES_DATA(cve_number)
                                        ON UPDATE CASCADE
                                        ON DELETE NO ACTION,
    CONSTRAINT                      VULNERABILITY_INSTANCES_SF_FK  FOREIGN KEY(software_id)
                                        REFERENCES SOFTWARE_FIRMWARE(software_id)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION
    );

CREATE TABLE APT_CVE_SCORING(
    cve_number                      VARCHAR(14)                    NOT NULL,
    apt_group                       VARCHAR(25)                    NOT NULL,
    score                           DECIMAL(3, 2)                  NOT NULL,
    reasoning                       VARCHAR(5000)                  NULL,
    CONSTRAINT                      VULNERABILITY_INSTANCES_PK
                                        PRIMARY KEY(cve_number, apt_group),
    CONSTRAINT                      APT_CVE_SCORING_VD_FK          FOREIGN KEY(cve_number)
                                        REFERENCES VULNERABILITIES_DATA(cve_number)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      APT_CVE_SCORING_AG_FK          FOREIGN KEY(apt_group)
                                        REFERENCES APT_GROUPS(apt_group)
                                            ON UPDATE CASCADE
                                            ON DELETE NO ACTION,
    CONSTRAINT                      APT_CVE_SCORING_score
                                        CHECK (score >= 0.0 AND score <= 1.00)
    );
    