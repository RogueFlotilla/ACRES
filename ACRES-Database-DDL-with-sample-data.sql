/*************************************************************************************************/
/*               A.I.-enhanced Cyber Resiliency Evaluation System (ACRES) Database               */
/*************************************************************************************************/
/*                                                                                               */
/* Kristian Alleyne, Richard Flores, Claire Kamobaya, Matthew Penn                               */
/* Dr. Xiang Liu                                                                                 */
/* IT 310 A - Database Technology                                                                */
/* December 10, 2024                                                                             */
/*                                                                                               */
/*************************************************************************************************/
/*                                         CREATE SCHEMA                                         */
/*************************************************************************************************/
CREATE SCHEMA acres;

/*************************************************************************************************/
/*                                         SELECT SCHEMA                                         */
/*************************************************************************************************/
USE acres;

/*************************************************************************************************/
/*                                         CREATE TABLES                                         */
/*************************************************************************************************/
CREATE TABLE APT_GROUPS(
    apt_group                                   VARCHAR(250)                            NOT NULL,
    alias_names                                 VARCHAR(100)                            NULL,
    description                                 VARCHAR(5000)                           NOT NULL,
    CONSTRAINT                                  APT_GROUPS_PK PRIMARY KEY(apt_group)
    );

CREATE TABLE CRITICALITY_DEFINITIONS(
	criticality_value			INT								NOT NULL,
    criticality_name			VARCHAR(25)						NOT NULL,
    downtime_allowed			VARCHAR(25)						NOT NULL,
    CONSTRAINT 					CRITICALITY_DEFINITIONS_PK		PRIMARY KEY(criticality_value)
	);

CREATE TABLE VULNERABILITIES_DATA(
	cve_number					VARCHAR(14)						NOT NULL,
    nvd_score					DECIMAL(2, 1)					NOT NULL,
    cvss_version				CHAR(3)							NOT NULL,
    vector_string				VARCHAR(44)						NOT NULL,
	attack_vector				VARCHAR(16)						NOT NULL,
    attack_complexity			VARCHAR(6)						NOT NULL,
    privilege_required			VARCHAR(8)						NULL,
    user_interaction_required	VARCHAR(8)						NOT NULL,
    scope_changed				VARCHAR(9)						NULL,
	impact_confidentiality		VARCHAR(8)						NOT NULL,
    impact_integrity			VARCHAR(8)						NOT NULL,
	impact_availability			VARCHAR(8)						NOT NULL,
    base_score					DECIMAL(2, 1)					NOT NULL,
    base_severity				VARCHAR(14)						NOT NULL,
    exploitability_score		DECIMAL(3, 1)					NOT NULL,
    impact_score				DECIMAL(3, 1)					NOT NULL,
    description					VARCHAR(5000)					NOT NULL,
    CONSTRAINT 					VULNERABILITIES_DATA_PK	PRIMARY KEY(cve_number),
    CONSTRAINT 					VULNERABILITIES_DATA_cve_number
									CHECK (cve_number LIKE 'CVE-____-____%'
										AND LENGTH(cve_number) BETWEEN 13 AND 14),
    CONSTRAINT					VULNERABILITIES_DATA_cvss_version
									CHECK (cvss_version IN ('2.0', '3.0', '3.1', '4.0')),
	CONSTRAINT					VULNERABILITIES_DATA_attack_vector
									CHECK (attack_vector IN (
										'PHYSICAL', 'LOCAL', 'ADJACENT_NETWORK', 'NETWORK')),
	CONSTRAINT					VULNERABILITIES_DATA_attack_complexity
									CHECK (attack_complexity IN ('LOW', 'MEDIUM', 'HIGH')),
	CONSTRAINT					VULNERABILITIES_DATA_privilege_required
									CHECK (privilege_required IN (null, 'NONE', 'LOW', 'HIGH')),
	CONSTRAINT					VULNERABILITIES_DATA_user_interaction_required
									CHECK (user_interaction_required IN ('NONE', 'REQUIRED', True, False)),
	CONSTRAINT					VULNERABILITIES_DATA_scope_changed
									CHECK (privilege_required IN (null, 'UNCHANGED', 'CHANGED')),
	CONSTRAINT					VULNERABILITIES_DATA_impact_confidentiality
									CHECK (impact_confidentiality IN (
										'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
	CONSTRAINT					VULNERABILITIES_DATA_impact_integrity
									CHECK (impact_integrity IN (
										'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
	CONSTRAINT					VULNERABILITIES_DATA_impact_availability
									CHECK (impact_availability IN (
										'NONE', 'PARTIAL', 'COMPLETE', 'LOW', 'HIGH')),
	CONSTRAINT 					VULNERABILITIES_DATA_base_score
									CHECK (base_score >= 0.00 AND base_score <= 10.00),
	CONSTRAINT					VULNERABILITIES_DATA_base_severity
									CHECK (base_severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
	CONSTRAINT 					VULNERABILITIES_DATA_exploitability_score
									CHECK (exploitability_score >= 0.00
										AND exploitability_score <= 10.00),
	CONSTRAINT 					VULNERABILITIES_DATA_impact_score
									CHECK (impact_score >= 0.00 AND impact_score <= 10.00)
	);

CREATE TABLE INFRASTRUCTURE_CATEGORIES(
    category_id					INT								NOT NULL AUTO_INCREMENT,
    category_name				VARCHAR(100)					NOT NULL,
    CONSTRAINT 					INFRASTRUCTURE_CATEGORIES_PK	PRIMARY KEY(category_id)
    );

CREATE TABLE INFRASTRUCTURE_NODES(
    infra_id					INT								NOT NULL AUTO_INCREMENT,
    serial_number				VARCHAR(25)						NOT NULL,
    infra_make					VARCHAR(25)						NOT NULL,
    infra_model					VARCHAR(25)						NOT NULL,
    description					VARCHAR(5000)					NULL,
    category_id					INT								NOT NULL,
    CONSTRAINT 					INFRASTRUCTURE_NODES_PK			PRIMARY KEY(infra_id)
	);
    
CREATE TABLE ENDPOINT_NODES(
	endpoint_id					INT								NOT NULL AUTO_INCREMENT,
    endpoint_name				VARCHAR(100)					NOT NULL,
    CONSTRAINT 					INFRASTRUCTURE_NODES_PK			PRIMARY KEY(endpoint_id)
	);
    
CREATE TABLE SOFTWARE_FIRMWARE(
	software_id					INT								NOT NULL AUTO_INCREMENT,
    software_make				VARCHAR(50)						NOT NULL,
    software_name				VARCHAR(100)					NOT NULL,
    software_version			VARCHAR(25)						NOT NULL,
    CONSTRAINT 					SOFTWARE_FIRMWARE_PK			PRIMARY KEY(software_id),
    CONSTRAINT					CUSTOMER_EMAIL UNIQUE(
		software_make, software_name, software_version)
	);
    
CREATE TABLE SYSTEM_SCORING(
	apt_group					VARCHAR(25)						NOT NULL,
    score_name					VARCHAR(9)						NOT NULL,
    score						DECIMAL(3, 2)					NOT NULL,
    reasoning					VARCHAR(5000)					NULL,
    remediations				JSON							NULL,
    CONSTRAINT 					SYSTEM_SCORING_PK				PRIMARY KEY(apt_group, score_name),
    CONSTRAINT 					SYSTEM_SCORING_AG_FK			FOREIGN KEY(apt_group)
									REFERENCES APT_GROUPS(apt_group)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
    CONSTRAINT					SYSTEM_SCORING_score_name
									CHECK (score_name IN ('Physical', 'Personnel', 'Policies')),
	CONSTRAINT 					SYSTEM_SCORING_score
									CHECK (score >= 0.0
										AND score <= 1.00)
    );

CREATE TABLE FUNCTION_DEFINITIONS(
	function_number		VARCHAR(4)						NOT NULL,
    function_name		VARCHAR(100)					NOT NULL,
	work_area			CHAR(100)						NOT NULL,
	criticality_value	INT								NOT NULL,
	CONSTRAINT 			FUNCTION_DEFINITIONS_PK 		PRIMARY KEY(function_number),
    CONSTRAINT 			FUNCTION_DEFINITIONS_CD_FK			FOREIGN KEY(criticality_value)
							REFERENCES CRITICALITY_DEFINITIONS(criticality_value)
								ON UPDATE CASCADE
								ON DELETE NO ACTION
	);

CREATE TABLE FUNCTION_MAPPING(
	endpoint_id					INT								NOT NULL,
    function_number				VARCHAR(4)						NOT NULL,
    CONSTRAINT 					FUNCTION_MAPPING_PK 			PRIMARY KEY(
		endpoint_id, function_number),
    CONSTRAINT 					FUNCTION_MAPPING_IN_FK  			FOREIGN KEY(endpoint_id)
									REFERENCES ENDPOINT_NODES(endpoint_id)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
    CONSTRAINT 					FUNCTION_MAPPING_FD_FK  			FOREIGN KEY(function_number)
									REFERENCES FUNCTION_DEFINITIONS(function_number)
										ON UPDATE CASCADE
										ON DELETE NO ACTION
	);
    
CREATE TABLE SOFTWARE_FIRMWARE_MAPPING(
	endpoint_id					INT								NOT NULL,
	software_id					INT								NOT NULL,
    CONSTRAINT 					SOFTWARE_FIRMWARE_MAPPING_PK	PRIMARY KEY(endpoint_id, software_id),
    CONSTRAINT 					SOFTWARE_FIRMWARE_MAPPING_EN_FK	FOREIGN KEY(endpoint_id)
									REFERENCES ENDPOINT_NODES(endpoint_id)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
	CONSTRAINT 					SOFTWARE_FIRMWARE_MAPPING_SF_FK	FOREIGN KEY(software_id)
									REFERENCES SOFTWARE_FIRMWARE(software_id)
										ON UPDATE CASCADE
										ON DELETE NO ACTION
	);
    
CREATE TABLE VULNERABILITY_INSTANCES(
	cve_number					VARCHAR(14)						NOT NULL,
    software_id					INT								NOT NULL,
    CONSTRAINT 					VULNERABILITY_INSTANCES_PK		PRIMARY KEY(
		cve_number, software_id),
    CONSTRAINT 					VULNERABILITY_INSTANCES_DV_FK	FOREIGN KEY(cve_number)
									REFERENCES VULNERABILITIES_DATA(cve_number)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
    CONSTRAINT 					VULNERABILITY_INSTANCES_SF_FK	FOREIGN KEY(software_id)
									REFERENCES SOFTWARE_FIRMWARE(software_id)
										ON UPDATE CASCADE
										ON DELETE NO ACTION
	);

CREATE TABLE APT_CVE_SCORING(
	cve_number					VARCHAR(14)						NOT NULL,
    apt_group					VARCHAR(25)						NOT NULL,
    score						DECIMAL(3, 2)					NOT NULL,
    reasoning					VARCHAR(5000)					NULL,
    CONSTRAINT 					VULNERABILITY_INSTANCES_PK		PRIMARY KEY(cve_number, apt_group),
    CONSTRAINT 					APT_CVE_SCORING_VD_FK			FOREIGN KEY(cve_number)
									REFERENCES VULNERABILITIES_DATA(cve_number)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
	CONSTRAINT 					APT_CVE_SCORING_AG_FK			FOREIGN KEY(apt_group)
									REFERENCES APT_GROUPS(apt_group)
										ON UPDATE CASCADE
										ON DELETE NO ACTION,
	CONSTRAINT 					APT_CVE_SCORING_score
									CHECK (score >= 0.0
										AND score <= 1.00)
	);

/*************************************************************************************************/
/*                                          INSERT DATA                                          */
/*************************************************************************************************/
# INSERT INTO APT_GROUPS VALUES(apt_group, alias_names, description);
# more available at: https://attack.mitre.org/groups/
# more availabe at: https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/edit?gid=2069598202#gid=2069598202
INSERT INTO APT_GROUPS VALUES("_None_", null, "No Description");
INSERT INTO APT_GROUPS VALUES("admin@338", null, "admin@338 is a China-based cyber threat group. It has previously used newsworthy events as lures to deliver malware and has primarily targeted organizations involved in financial, economic, and trade policy, typically using publicly available RATs such as PoisonIvy, as well as some non-public backdoors.");
INSERT INTO APT_GROUPS VALUES("Ajax Security Team", null, "Ajax Security Team is a group that has been active since at least 2010 and believed to be operating out of Iran. By 2014, the group transitioned from website defacement operations to malware-based cyber espionage campaigns targeting the US defense industrial base and Iranian users of anti-censorship technologies.");
INSERT INTO APT_GROUPS VALUES("Akira", null, "Akira is a ransomware variant and ransomware deployment entity active since at least March 2023. Akira uses compromised credentials to access single-factor external access mechanisms such as VPNs for initial access, then various publicly available tools and techniques for lateral movement.");
INSERT INTO APT_GROUPS VALUES("ALLANITE", null, "ALLANITE is a suspected Russian cyber espionage group, that has primarily targeted the electric utility sector within the US and UK. The group’s tactics are similar to Dragonfly, although ALLANITE's capabilities have not exhibited disruptive or destructive actions.");
INSERT INTO APT_GROUPS VALUES("Andariel", null, "Andariel is a North Korean state-sponsored threat group active since at least 2009, targeting South Korean government agencies, military organizations, and various domestic companies.");
INSERT INTO APT_GROUPS VALUES("Aoqin Dragon", null, "Aoqin Dragon is a suspected Chinese cyber espionage group that has been active since at least 2013, targeting government, education, and telecommunication organizations in Australia, Cambodia, Hong Kong, Singapore, and Vietnam.");
INSERT INTO APT_GROUPS VALUES("APT-C-23", null, "APT-C-23 is a threat group active since at least 2014, primarily targeting the Middle East, including Israeli military assets. The group has developed mobile spyware targeting Android and iOS devices since 2017.");
INSERT INTO APT_GROUPS VALUES("APT-C-36", null, "APT-C-36 is a suspected South America espionage group that has been active since at least 2018, primarily targeting Colombian government institutions and important corporations in the financial and petroleum sectors.");
INSERT INTO APT_GROUPS VALUES("APT1", null, "APT1 is a Chinese threat group attributed to Unit 61398 of the People’s Liberation Army. The group has engaged in extensive cyber espionage campaigns against a variety of sectors, especially aerospace, telecommunications, and financial sectors.");
INSERT INTO APT_GROUPS VALUES("APT10", "Stone Panda", "A Chinese-linked group targeting managed service providers and clients with spear-phishing and public-facing application exploits, deploying malware such as ChChes and Quasar RAT for intellectual property theft and long-term persistence.");
INSERT INTO APT_GROUPS VALUES("APT12", null, "APT12 is a Chinese cyber espionage group active since at least 2014, primarily targeting media outlets, high-tech companies, and various government entities.");
INSERT INTO APT_GROUPS VALUES("APT16", null, "APT16 is a Chinese threat group known for spearphishing campaigns targeting Japanese and Taiwanese organizations.");
INSERT INTO APT_GROUPS VALUES("APT17", null, "APT17 is a Chinese threat group known for its targeting of US government entities, defense industries, and legal firms, primarily utilizing network intrusions.");
INSERT INTO APT_GROUPS VALUES("APT18", null, "APT18 is a Chinese threat group that has operated since 2009 and targets industries such as technology, human rights organizations, and healthcare.");
INSERT INTO APT_GROUPS VALUES("APT19", "Codoso Team", "APT19 is a Chinese group targeting industries like defense, finance, energy, and legal services. The group is known for its phishing campaigns and potential overlap with the Deep Panda group.");
INSERT INTO APT_GROUPS VALUES("APT27", "Emissary Panda", "A Chinese state-sponsored group targeting government and critical infrastructure, exploiting networking vulnerabilities with advanced lateral movement, deploying custom malware like HyperBro and PlugX for espionage.");
INSERT INTO APT_GROUPS VALUES("APT28", "Fancy Bear", "APT28 is a Russian threat group linked to GRU military intelligence, known for spear-phishing campaigns targeting NATO, governments, and political institutions, with custom malware like X-Agent.");
INSERT INTO APT_GROUPS VALUES("APT29", "Cozy Bear", "APT29 is a Russian group associated with the Foreign Intelligence Service (SVR). Known for targeting government and research organizations, APT29 uses advanced living-off-the-land techniques and custom malware like CloudDuke.");
INSERT INTO APT_GROUPS VALUES("APT3", "Gothic Panda", "APT3 is a China-based group attributed to China’s Ministry of State Security. It is responsible for campaigns like Operation Clandestine Fox and targets industries like aerospace and defense.");
INSERT INTO APT_GROUPS VALUES("APT30", null, "APT30 is a Chinese cyber espionage group, often targeting government and political institutions in Southeast Asia, with a focus on intelligence collection.");
INSERT INTO APT_GROUPS VALUES("APT31", "Zirconium", "Chinese-linked group targeting government and technology sectors. TTPs include: Use of novel malware families and custom-built tools. Exploitation of zero-day vulnerabilities in popular software. Advanced techniques for lateral movement and privilege escalation. Deployment of backdoors like SOGU and JNDI. Targeting of intellectual property and sensitive government information. Sophisticated methods for maintaining long-term persistence in compromised networks.");
INSERT INTO APT_GROUPS VALUES("APT32", "OceanLotus", "APT32 is a Vietnamese state-sponsored cyber espionage group known for targeting private industries and government organizations across Southeast Asia.");
INSERT INTO APT_GROUPS VALUES("APT33", "Elfin", "APT33 is an Iranian group focused on targeting the aviation and energy sectors, particularly in the US, Saudi Arabia, and South Korea.");
INSERT INTO APT_GROUPS VALUES("APT34", "OilRig", "An Iranian group focusing on Middle Eastern organizations, utilizing spear-phishing and public-facing application exploits, deploying malware such as TRIGONA and HELMINTH for persistence via web shells.");
INSERT INTO APT_GROUPS VALUES("APT35", "Charming Kitten", "An Iranian-linked group targeting government and defense sectors, using spear-phishing and social engineering, deploying custom malware like POWERSTATS and targeting nuclear and military entities.");
INSERT INTO APT_GROUPS VALUES("APT36", "Transparent Tribe", "Pakistan-linked group focusing on government and military targets. TTPs include: Spear-phishing campaigns with geopolitical themes. Use of malicious macro-enabled documents for initial compromise. Deployment of custom RATs like Crimson and BreachRAT. Extensive use of social engineering techniques. Targeting of defense and government organizations in South Asia. Advanced persistence mechanisms and data exfiltration methods.");
INSERT INTO APT_GROUPS VALUES("APT37", "Reaper", "APT37 is a North Korean cyber espionage group targeting South Korea and other regions, primarily focusing on government and defense entities.");
INSERT INTO APT_GROUPS VALUES("APT38", "Lazarus Subgroup", "APT38 is a North Korean group specialized in financially motivated attacks, known for targeting the SWIFT banking system, executing theft operations involving millions of dollars.");
INSERT INTO APT_GROUPS VALUES("APT39", "Chafer", "APT39 is an Iranian cyber espionage group, targeting telecommunications, travel, and other sectors to gather intelligence and personal data.");
INSERT INTO APT_GROUPS VALUES("APT40", "TEMP.Periscope", "A Chinese group targeting maritime industries through spear-phishing and watering hole attacks, deploying custom malware like Derusbi and Gh0st RAT to maintain long-term persistence and exfiltrate sensitive data.");
INSERT INTO APT_GROUPS VALUES("APT41", null, "APT41 is a Chinese-linked espionage and financially motivated group, known for supply chain attacks and exploiting vulnerabilities in software development processes.");
INSERT INTO APT_GROUPS VALUES("Aquatic Panda", null, "Aquatic Panda is a China-based group focused on intelligence collection and industrial espionage, primarily targeting telecommunications and technology sectors.");
INSERT INTO APT_GROUPS VALUES("Axiom", null, "Axiom is a suspected Chinese cyber espionage group, targeting aerospace, defense, government, and manufacturing sectors.");
INSERT INTO APT_GROUPS VALUES("BackdoorDiplomacy", null, "BackdoorDiplomacy is a cyber espionage group targeting Ministries of Foreign Affairs and telecommunications companies in Africa, Europe, the Middle East, and Asia.");
INSERT INTO APT_GROUPS VALUES("BITTER", null, "BITTER is a South Asian cyber espionage group targeting government, energy, and engineering sectors in Pakistan, China, Bangladesh, and Saudi Arabia.");
INSERT INTO APT_GROUPS VALUES("BlackOasis", null, "BlackOasis is a Middle Eastern group targeting prominent individuals like opposition activists and journalists, often associated with Gamma Group customers.");
INSERT INTO APT_GROUPS VALUES("BlackTech", null, "BlackTech is a suspected Chinese cyber espionage group targeting organizations across East Asia, particularly those in media and electronics manufacturing sectors.");
INSERT INTO APT_GROUPS VALUES("Blue Mockingbird", null, "Blue Mockingbird is a cluster of activity involving Monero cryptocurrency-mining payloads, first observed in December 2019.");
INSERT INTO APT_GROUPS VALUES("BRONZE BUTLER", null, "BRONZE BUTLER is a Chinese cyber espionage group targeting Japanese organizations, particularly in government and biotechnology sectors.");
INSERT INTO APT_GROUPS VALUES("Carbanak", null, "Carbanak is a financially motivated group targeting financial institutions with spear-phishing campaigns followed by fraudulent banking operations.");
INSERT INTO APT_GROUPS VALUES("Chimera", null, "Chimera is a China-based threat group targeting the semiconductor industry and airline industry in Taiwan and beyond.");
INSERT INTO APT_GROUPS VALUES("Cinnamon Tempest", null, "Cinnamon Tempest is a China-based group deploying ransomware based on Babuk’s source code, targeting intellectual property theft rather than financial gain.");
INSERT INTO APT_GROUPS VALUES("Cleaver", null, "Cleaver is an Iranian group responsible for Operation Cleaver, targeting critical infrastructure across multiple countries.");
INSERT INTO APT_GROUPS VALUES("Cobalt Group", null, "Cobalt Group is a financially motivated threat group, targeting financial institutions globally through malware designed to manipulate ATMs and card processing systems.");
INSERT INTO APT_GROUPS VALUES("Confucius", null, "Confucius is a South Asian espionage group targeting military and government organizations, with overlapping tools and tactics with Patchwork.");
INSERT INTO APT_GROUPS VALUES("CopyKittens", null, "CopyKittens is an Iranian cyber espionage group active since 2013, targeting government and private sectors globally, including the US, Germany, and Israel.");
INSERT INTO APT_GROUPS VALUES("CURIUM", null, "CURIUM is an Iranian group that focuses on establishing long-term social engineering relationships before delivering malware.");
INSERT INTO APT_GROUPS VALUES("CyberAv3ngers", null, "CyberAv3ngers is an IRGC-affiliated group targeting Israel's critical infrastructure, operating since 2020.");
INSERT INTO APT_GROUPS VALUES("Dark Caracal", null, "Dark Caracal is a Lebanese group attributed to the General Directorate of General Security, active since at least 2012, conducting global cyber espionage operations.");
INSERT INTO APT_GROUPS VALUES("Darkhotel", null, "Darkhotel is a South Korean group targeting executives in East Asia, often via hotel networks.");
INSERT INTO APT_GROUPS VALUES("DarkHydrus", null, "DarkHydrus is a Middle Eastern group targeting government agencies and educational institutions using open-source tools.");
INSERT INTO APT_GROUPS VALUES("DarkVishnya", null, "DarkVishnya is a financially motivated actor targeting banks in Eastern Europe, often using physical devices for network access.");
INSERT INTO APT_GROUPS VALUES("Deep Panda", null, "Deep Panda is a Chinese group targeting industries like healthcare and telecommunications, linked to the Anthem intrusion.");
INSERT INTO APT_GROUPS VALUES("Dragonfly", "Energetic Bear", "Dragonfly is a Russian group targeting critical infrastructure sectors such as defense, energy, and aviation, often using supply chain attacks.");
INSERT INTO APT_GROUPS VALUES("DragonOK", null, "DragonOK is a Chinese group targeting Japanese organizations via phishing campaigns, deploying malware such as PlugX and PoisonIvy.");
INSERT INTO APT_GROUPS VALUES("Earth Lusca", null, "Earth Lusca is a China-based group targeting governments, media, and research organizations across Asia and Europe.");
INSERT INTO APT_GROUPS VALUES("Elderwood", null, "Elderwood is a Chinese group linked to the Operation Aurora attack on Google, targeting defense and human rights organizations.");
INSERT INTO APT_GROUPS VALUES("Ember Bear", null, "Ember Bear is a Russian group targeting Ukraine and Georgia, linked to the WhisperGate attacks.");
INSERT INTO APT_GROUPS VALUES("Equation", null, "Equation is a highly sophisticated group believed to be linked to the NSA, known for firmware-based attacks and advanced malware.");
INSERT INTO APT_GROUPS VALUES("Equation Group", null, "Believed to be linked to the NSA, this group is known for highly sophisticated operations targeting high-value entities worldwide. TTPs include exploiting zero-day vulnerabilities in firmware and hard drive controllers, using advanced malware such as EquationDrug (modular platform) and GrayFish (validator implant). Their persistence techniques survive system reinstalls, allowing them to target air-gapped networks effectively. They employ complex multi-stage attack chains along with advanced encryption methods for secure communications.");
INSERT INTO APT_GROUPS VALUES("Evilnum", null, "Evilnum is a financially motivated group active since at least 2018, targeting financial institutions.");
INSERT INTO APT_GROUPS VALUES("EXOTIC LILY", null, "EXOTIC LILY is a financially motivated group linked to Wizard Spider, deploying ransomware such as Conti.");
INSERT INTO APT_GROUPS VALUES("Ferocious Kitten", null, "Ferocious Kitten is an Iranian group targeting Persian-speaking individuals, often using custom malware to gather intelligence.");
INSERT INTO APT_GROUPS VALUES("FIN10", null, "FIN10 is a financially motivated group extorting North American organizations through data theft and ransomware.");
INSERT INTO APT_GROUPS VALUES("FIN11", null, "A financially motivated group linked to Eastern Europe, conducting large-scale phishing campaigns with malicious documents and malware like FRIENDSPEAK and MIXLABEL, focused on financial gain and evasion of detection.");
INSERT INTO APT_GROUPS VALUES("FIN13", null, "FIN13 is a Latin American financial cyber threat group targeting financial institutions for theft of intellectual property.");
INSERT INTO APT_GROUPS VALUES("FIN4", null, "FIN4 is a financial group focused on capturing email credentials in the financial market, particularly in the healthcare and pharmaceutical sectors.");
INSERT INTO APT_GROUPS VALUES("FIN5", null, "FIN5 is a financially motivated group targeting payment card data in the restaurant, gaming, and hotel industries, active since 2008.");
INSERT INTO APT_GROUPS VALUES("FIN6", null, "FIN6 is a cybercrime group known for stealing payment card data from point-of-sale (PoS) systems in the hospitality and retail sectors.");
INSERT INTO APT_GROUPS VALUES("FIN7", null, "FIN7 is a financially motivated group targeting the retail, restaurant, and hospitality sectors, using phishing and malware such as Carbanak for payment card theft.");
INSERT INTO APT_GROUPS VALUES("FIN8", null, "FIN8 is a financially motivated group targeting PoS devices in hospitality, retail, and financial sectors, with ransomware and cryptocurrency mining malware.");
INSERT INTO APT_GROUPS VALUES("Fox Kitten", null, "Fox Kitten is an Iranian group targeting critical infrastructure sectors, including oil and gas, and government organizations in the Middle East.");
INSERT INTO APT_GROUPS VALUES("GALLIUM", null, "GALLIUM is a Chinese cyber espionage group targeting telecommunications and financial institutions, with a focus on the Operation Soft Cell campaign.");
INSERT INTO APT_GROUPS VALUES("Gallmaker", null, "Gallmaker is a cyber espionage group targeting defense and military sectors using fileless malware and leveraging legitimate tools for espionage operations.");
INSERT INTO APT_GROUPS VALUES("Gamaredon Group", null, "Gamaredon Group is a Russian threat group targeting Ukrainian government entities, using spear-phishing, VBA macros, and PowerShell for data exfiltration.");
INSERT INTO APT_GROUPS VALUES("GCMAN", null, "GCMAN is a group targeting banks for fraudulent transfers to e-currency services, often using sophisticated financial tools.");
INSERT INTO APT_GROUPS VALUES("GOLD SOUTHFIELD", null, "GOLD SOUTHFIELD is a financially motivated group operating the REvil Ransomware-as-a-Service (RaaS) platform, active since 2018.");
INSERT INTO APT_GROUPS VALUES("Gorgon Group", null, "Gorgon Group is a Pakistan-based group targeting government organizations in the US, Russia, Spain, and the UK through criminal and espionage attacks.");
INSERT INTO APT_GROUPS VALUES("Group5", null, "Group5 is a suspected Iranian group targeting Syrian opposition via spear-phishing and watering hole attacks using RATs like njRAT and NanoCore.");
INSERT INTO APT_GROUPS VALUES("HAFNIUM", null, "HAFNIUM is a Chinese state-sponsored group targeting US entities across sectors like infectious disease research, law firms, and defense contractors.");
INSERT INTO APT_GROUPS VALUES("HEXANE", null, "HEXANE is a cyber espionage group targeting oil & gas, telecommunications, and ISPs in the Middle East and Africa, with tactics similar to APT33 and OilRig.");
INSERT INTO APT_GROUPS VALUES("Higaisa", null, "Higaisa is a suspected South Korean group targeting public organizations in North Korea, Japan, Russia, and other countries for espionage purposes.");
INSERT INTO APT_GROUPS VALUES("Inception", null, "Inception is a Russian cyber espionage group targeting industries worldwide, particularly government entities in Europe and Asia.");
INSERT INTO APT_GROUPS VALUES("IndigoZebra", null, "IndigoZebra is a Chinese group targeting Central Asian governments through sophisticated phishing and malware deployment.");
INSERT INTO APT_GROUPS VALUES("Indrik Spider", null, "Indrik Spider is a Russian group known for ransomware operations like BitPaymer and WastedLocker, targeting financial and technology sectors.");
INSERT INTO APT_GROUPS VALUES("Ke3chang", null, "Ke3chang is a Chinese cyber espionage group targeting diplomatic, military, and oil organizations, often using spear-phishing campaigns.");
INSERT INTO APT_GROUPS VALUES("Kimsuky", null, "Kimsuky is a North Korean group targeting think tanks, government organizations, and individuals involved in Korean Peninsula issues.");
INSERT INTO APT_GROUPS VALUES("LAPSUS$", null, "LAPSUS$ is a cybercriminal group active since 2021, specializing in large-scale social engineering and extortion campaigns against global organizations.");
INSERT INTO APT_GROUPS VALUES("Lazarus Group", null, "Lazarus Group is a North Korean group known for financial theft and espionage, deploying malware like HOPLIGHT and FALLCHILL against financial institutions and cryptocurrency exchanges.");
INSERT INTO APT_GROUPS VALUES("LazyScripter", null, "LazyScripter is a group targeting the airline industry using open-source toolsets for cyber espionage campaigns.");
INSERT INTO APT_GROUPS VALUES("Leafminer", null, "Leafminer is an Iranian group targeting Middle Eastern government organizations and businesses, active since 2017.");
INSERT INTO APT_GROUPS VALUES("Leviathan", "TEMP.Periscope", "Leviathan is a Chinese group targeting maritime industries and defense contractors for intellectual property theft through spear-phishing and malware deployment.");
INSERT INTO APT_GROUPS VALUES("Lotus Blossom", null, "Lotus Blossom is a Chinese group targeting Southeast Asian government and military organizations, often using spear-phishing attacks.");
INSERT INTO APT_GROUPS VALUES("LuminousMoth", null, "LuminousMoth is a Chinese-speaking group targeting government entities in Myanmar, the Philippines, and Southeast Asia using custom malware.");
INSERT INTO APT_GROUPS VALUES("Machete", null, "Machete is a Spanish-speaking cyber espionage group targeting Latin American organizations with spear-phishing campaigns focusing on government and diplomatic entities.");
INSERT INTO APT_GROUPS VALUES("Magic Hound", null, "Magic Hound is an Iranian group conducting cyber espionage campaigns against government and military personnel in Europe, the US, and the Middle East.");
INSERT INTO APT_GROUPS VALUES("Malteiro", null, "Malteiro is a Brazilian financially motivated group targeting victims in Latin America with the Mispadu banking trojan distributed via Malware-as-a-Service.");
INSERT INTO APT_GROUPS VALUES("menuPass", null, "menuPass is a Chinese group active since 2006, targeting industries like aerospace, government, and defense, often linked to the MSS.");
INSERT INTO APT_GROUPS VALUES("Metador", null, "Metador is a suspected cyber espionage group targeting telecommunication companies and ISPs in the Middle East and Africa.");
INSERT INTO APT_GROUPS VALUES("Moafee", null, "Moafee is a Chinese group targeting Japanese organizations with phishing and malware attacks, overlapping with the DragonOK group.");
INSERT INTO APT_GROUPS VALUES("Mofang", null, "Mofang is a Chinese group targeting critical infrastructure in Myanmar and other countries, using imitative tactics to compromise networks.");
INSERT INTO APT_GROUPS VALUES("Molerats", null, "Molerats is an Arabic-speaking group targeting Middle Eastern, European, and US organizations through politically motivated campaigns.");
INSERT INTO APT_GROUPS VALUES("Moses Staff", null, "Moses Staff is an Iranian group targeting Israeli companies, focused on leaking sensitive data without demanding a ransom.");
INSERT INTO APT_GROUPS VALUES("MoustachedBouncer", null, "MoustachedBouncer is a group targeting foreign embassies in Belarus, using espionage campaigns to collect sensitive diplomatic data.");
INSERT INTO APT_GROUPS VALUES("MuddyWater", null, "MuddyWater is an Iranian group targeting Middle Eastern and Central Asian organizations with spear-phishing attacks deploying malware like POWERSTATS.");
INSERT INTO APT_GROUPS VALUES("Mustang Panda", null, "Mustang Panda is a Chinese group targeting government entities, nonprofits, and religious organizations in the US, Europe, and Southeast Asia.");
INSERT INTO APT_GROUPS VALUES("Mustard Tempest", null, "Mustard Tempest is an initial access broker operating the SocGholish network since 2017, collaborating with Indrik Spider for additional malware deployment.");
INSERT INTO APT_GROUPS VALUES("Naikon", null, "Naikon is a Chinese cyber espionage group targeting Southeast Asian governments and international organizations like the UNDP.");
INSERT INTO APT_GROUPS VALUES("NEODYMIUM", null, "NEODYMIUM is a group active since 2016, targeting Turkish victims with campaigns linked to BlackOasis and PROMETHIUM.");
INSERT INTO APT_GROUPS VALUES("Nomadic Octopus", null, "Nomadic Octopus is a Russian group targeting Central Asian governments and diplomatic missions, using custom Android and Windows malware.");
INSERT INTO APT_GROUPS VALUES("OilRig", null, "OilRig is an Iranian group targeting Middle Eastern and international organizations through supply chain attacks and public-facing application exploits.");
INSERT INTO APT_GROUPS VALUES("Orangeworm", null, "Orangeworm is a group targeting healthcare organizations globally, using malware like Kwampirs for espionage and intellectual property theft.");
INSERT INTO APT_GROUPS VALUES("Patchwork", "Dropping Elephant", "Patchwork is a group linked to India, targeting diplomatic entities and think tanks through spear-phishing with malware like BADNEWS.");
INSERT INTO APT_GROUPS VALUES("PittyTiger", null, "PittyTiger is a Chinese group using various malware to maintain command and control, targeting global organizations.");
INSERT INTO APT_GROUPS VALUES("PLATINUM", null, "PLATINUM is an espionage group targeting South and Southeast Asian governments, active since at least 2009.");
INSERT INTO APT_GROUPS VALUES("POLONIUM", null, "POLONIUM is a Lebanese group targeting Israeli organizations, collaborating with Iranian actors for advanced espionage campaigns.");
INSERT INTO APT_GROUPS VALUES("Poseidon Group", null, "Poseidon Group is a Portuguese-speaking group using blackmail tactics, targeting companies for information theft and forcing them to contract Poseidon as a security firm.");
INSERT INTO APT_GROUPS VALUES("PROMETHIUM", null, "PROMETHIUM is an espionage group targeting Turkish organizations, operating globally with overlapping characteristics with NEODYMIUM.");
INSERT INTO APT_GROUPS VALUES("Putter Panda", null, "Putter Panda is a Chinese group linked to Unit 61486 of the PLA, targeting aerospace and defense sectors globally.");
INSERT INTO APT_GROUPS VALUES("Rancor", null, "Rancor is a group targeting Southeast Asian entities using politically motivated lures to deploy malicious documents.");
INSERT INTO APT_GROUPS VALUES("Rocke", null, "Rocke is a Chinese-speaking group focused on cryptojacking by leveraging victim systems to mine cryptocurrency, active since at least 2018.");
INSERT INTO APT_GROUPS VALUES("RTM", null, "RTM is a Russian cybercriminal group targeting remote banking systems in Russia and neighboring countries with malware.");
INSERT INTO APT_GROUPS VALUES("Sandworm Team", null, "Sandworm Team is a Russian group targeting critical infrastructure, deploying destructive malware like BlackEnergy and Industroyer.");
INSERT INTO APT_GROUPS VALUES("Scarlet Mimic", null, "Scarlet Mimic is a Chinese-linked group targeting minority rights activists through espionage campaigns with custom malware.");
INSERT INTO APT_GROUPS VALUES("Scattered Spider", null, "Scattered Spider is an English-speaking cybercriminal group targeting telecommunications and technology companies, deploying ransomware for financial gain.");
INSERT INTO APT_GROUPS VALUES("SideCopy", null, "SideCopy is a Pakistani group targeting Indian and Afghani government personnel through spear-phishing campaigns mimicking Sidewinder tactics.");
INSERT INTO APT_GROUPS VALUES("Sidewinder", null, "Sidewinder is an Indian group targeting military and business entities across Asia, especially Pakistan and China, using advanced malware.");
INSERT INTO APT_GROUPS VALUES("Silence", null, "Silence is a financially motivated group targeting banks and ATMs, focused on fraudulent transfers using legitimate banking tools.");
INSERT INTO APT_GROUPS VALUES("Silent Librarian", null, "Silent Librarian is an Iranian group targeting universities and government agencies for intellectual property theft, linked to the Iranian Mabna Institute.");
INSERT INTO APT_GROUPS VALUES("SilverTerrier", null, "SilverTerrier is a Nigerian cybercriminal group targeting organizations in the technology and manufacturing sectors, known for using commodity malware.");
INSERT INTO APT_GROUPS VALUES("Sowbug", null, "Sowbug is a group targeting South American and Southeast Asian government entities through espionage campaigns focused on data exfiltration.");
INSERT INTO APT_GROUPS VALUES("Stealth Falcon", null, "Stealth Falcon is a UAE-linked group targeting Emirati journalists, activists, and dissidents through spyware campaigns.");
INSERT INTO APT_GROUPS VALUES("Strider", null, "Strider is a group targeting victims in Russia, China, Sweden, and Iran, using sophisticated espionage malware for long-term operations.");
INSERT INTO APT_GROUPS VALUES("Suckfly", null, "Suckfly is a Chinese group targeting government and private-sector organizations in Asia and North America, active since at least 2014.");
INSERT INTO APT_GROUPS VALUES("TA2541", null, "TA2541 is a cybercriminal group targeting aviation, aerospace, and defense industries using remote access trojans (RATs) and phishing campaigns.");
INSERT INTO APT_GROUPS VALUES("TA459", null, "TA459 is a Chinese group targeting Russian, Belarusian, and Mongolian organizations through espionage campaigns.");
INSERT INTO APT_GROUPS VALUES("TA505", null, "TA505 is a financially motivated group known for large-scale malspam campaigns, distributing malware like Clop ransomware and FlawedAmmyy RAT.");
INSERT INTO APT_GROUPS VALUES("TA551", null, "TA551 is a financially motivated group active since 2018, targeting organizations with email-based malware distribution campaigns.");
INSERT INTO APT_GROUPS VALUES("TeamTNT", null, "TeamTNT is a group targeting cloud and container environments to deploy cryptocurrency miners and perform data theft.");
INSERT INTO APT_GROUPS VALUES("TEMP.Veles", null, "TEMP.Veles is a Russian group targeting critical infrastructure, using the TRITON malware framework to manipulate industrial safety systems.");
INSERT INTO APT_GROUPS VALUES("The White Company", null, "The White Company is a likely state-sponsored group targeting Pakistani government and military organizations, active since 2017.");
INSERT INTO APT_GROUPS VALUES("Threat Group-1314", null, "Threat Group-1314 is an unattributed group using compromised credentials to access victims’ remote access infrastructure.");
INSERT INTO APT_GROUPS VALUES("Threat Group-3390", null, "Threat Group-3390 is a Chinese group targeting aerospace, government, and defense sectors through web compromises and malware.");
INSERT INTO APT_GROUPS VALUES("Thrip", null, "Thrip is a Chinese-linked group targeting satellite communications, defense contractors, and telecommunications companies.");
INSERT INTO APT_GROUPS VALUES("ToddyCat", null, "ToddyCat is a sophisticated group active since 2020, targeting government and military organizations across Europe and Asia using custom loaders and multi-stage malware.");
INSERT INTO APT_GROUPS VALUES("Tonto Team", null, "Tonto Team is a Chinese group targeting government and military organizations in South Korea, Japan, and the US using spear-phishing and espionage malware.");
INSERT INTO APT_GROUPS VALUES("Transparent Tribe", null, "Transparent Tribe is a Pakistan-based group targeting Indian and Afghan defense and government organizations through spear-phishing and remote access trojans.");
INSERT INTO APT_GROUPS VALUES("Tropic Trooper", null, "Tropic Trooper is a group targeting government, healthcare, and high-tech industries in Taiwan and the Philippines using custom malware.");
INSERT INTO APT_GROUPS VALUES("Turla", "Snake", "Turla is a Russian group targeting government and diplomatic entities worldwide, using sophisticated malware like Snake and Carbon.");
INSERT INTO APT_GROUPS VALUES("UNC788", null, "UNC788 is an Iranian group targeting individuals in the Middle East using spear-phishing and malware deployment.");
INSERT INTO APT_GROUPS VALUES("Volatile Cedar", null, "Volatile Cedar is a Lebanese group targeting companies and institutions worldwide, focusing on espionage and political interests.");
INSERT INTO APT_GROUPS VALUES("Volt Typhoon", null, "Volt Typhoon is a Chinese state-sponsored group targeting critical infrastructure in the US, focusing on espionage and information gathering.");
INSERT INTO APT_GROUPS VALUES("Whitefly", null, "Whitefly is a Chinese group targeting Singapore-based organizations, primarily interested in stealing sensitive information, such as healthcare data.");
INSERT INTO APT_GROUPS VALUES("Windigo", null, "Windigo is a group compromising Linux and Unix servers since 2011, using the Ebury SSH backdoor to create a spam botnet.");
INSERT INTO APT_GROUPS VALUES("Windshift", null, "Windshift is a group targeting government departments and critical infrastructure in the Middle East for surveillance purposes.");
INSERT INTO APT_GROUPS VALUES("Winnti Group", null, "Winnti Group is a Chinese group targeting gaming and software companies through supply chain attacks, using malware like PlugX and ShadowPad.");
INSERT INTO APT_GROUPS VALUES("WIRTE", null, "WIRTE is a group targeting government and diplomatic organizations in the Middle East and Europe, using malware to exfiltrate sensitive data.");
INSERT INTO APT_GROUPS VALUES("Wizard Spider", null, "Wizard Spider is a Russia-based group known for operating TrickBot malware and deploying Ryuk and Conti ransomware in high-value campaigns.");
INSERT INTO APT_GROUPS VALUES("ZIRCONIUM", null, "ZIRCONIUM is a Chinese group targeting individuals involved in US presidential elections and international affairs, active since at least 2017.");

# INSERT INTO CRITICALITY_DEFINITIONS VALUES(criticality_value, criticality_name, downtime_allowed);
INSERT INTO CRITICALITY_DEFINITIONS VALUES(1, 'LOW', 'None');
INSERT INTO CRITICALITY_DEFINITIONS VALUES(2, 'MEDIUM', '1 month');
INSERT INTO CRITICALITY_DEFINITIONS VALUES(3, 'HIGH', 'Undetermined');

# INSERT INTO VULNERABILITIES_DATA VALUES();
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20256', 5.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N', 'NETWORK', 'LOW', 'NONE', 'NONE', 'CHANGED', 'NONE', 'LOW', 'NONE', 5.8, 'MEDIUM', 3.9, 1.4, 'Multiple vulnerabilities in the per-user-override feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to bypass a configured access control list (ACL) and allow traffic that should be denied to flow through an affected device. These vulnerabilities are due to a logic error that could occur when the affected software constructs and applies per-user-override rules. An attacker could exploit these vulnerabilities by connecting to a network through an affected device that has a vulnerable configuration. A successful exploit could allow the attacker to bypass the interface ACL and access resources that would should be protected.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20247', 4.3, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N', 'NETWORK', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'NONE', 'LOW', 'NONE', 4.3, 'MEDIUM', 2.8, 1.4, 'A vulnerability in the remote access SSL VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an authenticated, remote attacker to bypass a configured multiple certificate authentication policy and connect using only a valid username and password. This vulnerability is due to improper error handling during remote access VPN authentication. An attacker could exploit this vulnerability by sending crafted requests during remote access VPN session establishment. A successful exploit could allow the attacker to bypass the configured multiple certificate authentication policy while retaining the privileges and permissions associated with the original connection profile.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20200', 6.3, '3.1', 'CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H', 'NETWORK', 'HIGH', 'LOW', 'NONE', 'CHANGED', 'NONE', 'NONE', 'HIGH', 6.3, 'MEDIUM', 1.8, 4.0, 'A vulnerability in the Simple Network Management Protocol (SNMP) service of Cisco FXOS Software for Firepower 4100 Series and Firepower 9300 Security Appliances and of Cisco UCS 6300 Series Fabric Interconnects could allow an authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to the improper handling of specific SNMP requests. An attacker could exploit this vulnerability by sending a crafted SNMP request to an affected device. A successful exploit could allow the attacker to cause the affected device to reload, resulting in a DoS condition. Note: This vulnerability affects all supported SNMP versions. To exploit this vulnerability through SNMPv2c or earlier, an attacker must know the SNMP community string that is configured on an affected device. To exploit this vulnerability through SNMPv3, the attacker must have valid credentials for an SNMP user who is configured on the affected device.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20095', 8.6, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H', 'NETWORK', 'LOW', 'NONE', 'NONE', 'CHANGED', 'NONE', 'NONE', 'HIGH', 8.6, 'HIGH', 3.9, 4.0, 'A vulnerability in the remote access VPN feature of Cisco Adaptive Security Appliance (ASA) Software and Cisco Firepower Threat Defense (FTD) Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This vulnerability is due to improper handling of HTTPS requests. An attacker could exploit this vulnerability by sending crafted HTTPS requests to an affected system. A successful exploit could allow the attacker to cause resource exhaustion, resulting in a DoS condition.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20015', 6.7, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'HIGH', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 6.7, 'MEDIUM', 0.8, 5.9, 'A vulnerability in the CLI of Cisco Firepower 4100 Series, Cisco Firepower 9300 Security Appliances, and Cisco UCS 6200,6300,6400, and 6500 Series Fabric Interconnects could allow an authenticated, local attacker to inject unauthorized commands. This vulnerability is due to insufficient input validation of commands supplied by the user. An attacker could exploit this vulnerability by authenticating to a device and submitting crafted input to the affected command. A successful exploit could allow the attacker to execute unauthorized commands within the CLI. An attacker with Administrator privileges could also execute arbitrary commands on the underlying operating system of Cisco UCS 6400 and 6500 Series Fabric Interconnects with root-level privileges.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20934', 7.8, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 7.8, 'HIGH', 1.8, 5.9, 'In resolveAttributionSource of ServiceUtilities.cpp, there is a possible way to disable the microphone privacy indicator due to a permissions bypass. This could lead to local escalation of privilege with no additional execution privileges needed. User interaction is not needed for exploitation.Product: AndroidVersions: Android-12 Android-12L Android-13Android ID: A-258672042');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2018-0284', 6.5, '3.0', 'CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N', 'NETWORK', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 6.5, 'MEDIUM', 2.8, 3.6, 'A vulnerability in the local status page functionality of the Cisco Meraki MR, MS, MX, Z1, and Z3 product lines could allow an authenticated, remote attacker to modify device configuration files. The vulnerability occurs when handling requests to the local status page. An exploit could allow the attacker to establish an interactive session to the device with elevated privileges. The attacker could then use the elevated privileges to further compromise the device or obtain additional configuration data from the device that is being exploited.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-7999', 7.7, '2.0', 'AV:A/AC:L/Au:S/C:C/I:C/A:C', 'ADJACENT_NETWORK', 'LOW', 'SINGLE', False, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 7.7, 'HIGH', 5.1, 10.0, 'Cisco-Meraki MS, MR, and MX devices with firmware before 2014-09-24 allow remote authenticated users to install arbitrary firmware by leveraging unspecified HTTP handler access on the local network, aka Cisco-Meraki defect ID 00478565.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-7993', 3.3, '2.0', 'AV:A/AC:L/Au:N/C:P/I:N/A:N', 'ADJACENT_NETWORK', 'LOW', 'NONE', False, 'UNCHANGED', 'PARTIAL', 'NONE', 'NONE', 3.3, 'LOW', 6.5,2.9, 'Cisco-Meraki MS, MR, and MX devices with firmware before 2014-09-24 allow remote attackers to obtain sensitive credential information by leveraging unspecified HTTP handler access on the local network, aka Cisco-Meraki defect ID 00302012.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-7994', 5.4, '2.0', 'AV:A/AC:M/Au:N/C:P/I:P/A:P', 'ADJACENT_NETWORK', 'MEDIUM', 'NONE', False, 'UNCHANGED', 'PARTIAL', 'PARTIAL', 'PARTIAL', 5.4, 'MEDIUM', 5.5, 6.4, 'Cisco-Meraki MS, MR, and MX devices with firmware before 2014-09-24 allow remote attackers to execute arbitrary commands by leveraging knowledge of a cross-device secret and a per-device secret, and sending a request to an unspecified HTTP handler on the local network, aka Cisco-Meraki defect ID 00301991.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2016-6473', 6.5, '3.0', 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'ADJACENT_NETWORK', 'LOW', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'NONE', 'HIGH', 6.5, 'MEDIUM', 2.8, 3.6, 'A vulnerability in Cisco IOS on Catalyst Switches and Nexus 9300 Series Switches could allow an unauthenticated, adjacent attacker to cause a Layer 2 network storm. More Information: CSCuu69332, CSCux07028. Known Affected Releases: 15.2(3)E. Known Fixed Releases: 12.2(50)SE4 12.2(50)SE5 12.2(50)SQ5 12.2(50)SQ6 12.2(50)SQ7 12.2(52)EY4 12.2(52)SE1 12.2(53)EX 12.2(53)SE 12.2(53)SE1 12.2(53)SE2 12.2(53)SG10 12.2(53)SG11 12.2(53)SG2 12.2(53)SG9 12.2(54)SG1 12.2(55)EX3 12.2(55)SE 12.2(55)SE1 12.2(55)SE10 12.2(55)SE2 12.2(55)SE3 12.2(55)SE4 12.2(55)SE5 12.2(55)SE6 12.2(55)SE7 12.2(55)SE8 12.2(55)SE9 12.2(58)EZ 12.2(58)SE1 12.2(58)SE2 12.2(60)EZ 12.2(60)EZ1 12.2(60)EZ2 12.2(60)EZ3 12.2(60)EZ4 12.2(60)EZ5 12.2(60)EZ6 12.2(60)EZ7 12.2(60)EZ8 15.0(1)EY2 15.0(1)SE 15.0(1)SE2 15.0(1)SE3 15.0(2)EA 15.0(2)EB 15.0(2)EC 15.0(2)ED 15.0(2)EH 15.0(2)EJ 15.0(2)EJ1 15.0(2)EK1 15.0(2)EX 15.0(2)EX1 15.0(2)EX3 15.0(2)EX4 15.0(2)EX5 15.0(2)EY 15.0(2)EY1 15.0(2)EY2 15.0(2)EZ 15.0(2)SE 15.0(2)SE1 15.0(2)SE2 15.0(2)SE3 15.0(2)SE4 15.0(2)SE5 15.0(2)SE6 15.0(2)SE7 15.0(2)SE9 15.0(2)SG10 15.0(2)SG3 15.0(2)SG6 15.0(2)SG7 15.0(2)SG8 15.0(2)SG9 15.0(2a)EX5 15.1(2)SG 15.1(2)SG1 15.1(2)SG2 15.1(2)SG3 15.1(2)SG4 15.1(2)SG5 15.1(2)SG6 15.2(1)E 15.2(1)E1 15.2(1)E2 15.2(1)E3 15.2(1)EY 15.2(2)E 15.2(2)E3 15.2(2b)E.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2017-6606', 6.4, '3.0', 'CVSS:3.0/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H', 'PHYSICAL', 'HIGH', 'NONE', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 6.4, 'MEDIUM', 0.5, 5.9, 'A vulnerability in a startup script of Cisco IOS XE Software could allow an unauthenticated attacker with physical access to the targeted system to execute arbitrary commands on the underlying operating system with the privileges of the root user. More Information: CSCuz06639 CSCuz42122. Known Affected Releases: 15.6(1.1)S 16.1.2 16.2.0 15.2(1)E. Known Fixed Releases: Denali-16.1.3 16.2(1.8) 16.1(2.61) 15.6(2)SP 15.6(2)S1 15.6(1)S2 15.5(3)S3a 15.5(3)S3 15.5(2)S4 15.5(1)S4 15.4(3)S6a 15.4(3)S6 15.3(3)S8a 15.3(3)S8 15.2(5)E 15.2(4)E3 15.2(3)E5 15.0(2)SQD3 15.0(1.9.2)SQD3 3.9(0)E.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2017-3803', 4.7, '3.0', 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L', 'ADJACENT_NETWORK', 'LOW', 'NONE', 'NONE', 'CHANGED', 'NONE', 'NONE', 'LOW', 4.7, 'MEDIUM', 2.8, 1.4, 'A vulnerability in the Cisco IOS Software forwarding queue of Cisco 2960X and 3750X switches could allow an unauthenticated, adjacent attacker to cause a memory leak in the software forwarding queue that would eventually lead to a partial denial of service (DoS) condition. More Information: CSCva72252. Known Affected Releases: 15.2(2)E3 15.2(4)E1. Known Fixed Releases: 15.2(2)E6 15.2(4)E3 15.2(5)E1 15.2(5.3.28i)E1 15.2(6.0.49i)E 3.9(1)E.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2016-1425', 6.5, '3.0', 'CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'ADJACENT_NETWORK', 'LOW', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'NONE', 'HIGH', 6.5, 'MEDIUM', 2.8, 3.6, 'Cisco IOS 15.0(2)SG5, 15.1(2)SG3, 15.2(1)E, 15.3(3)S, and 15.4(1.13)S allows remote attackers to cause a denial of service (device crash) via a crafted LLDP packet, aka Bug ID CSCun66735.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2012-2697', 4.9, '2.0', 'AV:L/AC:L/Au:N/C:N/I:N/A:C', 'LOCAL', 'LOW', 'NONE', False, 'UNCHANGED', 'NONE', 'NONE', 'COMPLETE', 4.9, 'MEDIUM', 3.9, 6.9, 'Unspecified vulnerability in autofs, as used in Red Hat Enterprise Linux (RHEL) 5," allows local users to cause a denial of service (autofs crash and delayed mounts) or prevent mount expiration via unspecified vectors related to using an LDAP-based automount map.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2012-3440', 5.6, '2.0', 'AV:L/AC:H/Au:N/C:N/I:C/A:C', 'LOCAL', 'HIGH', 'NONE', False, 'UNCHANGED', 'NONE', 'COMPLETE', 'COMPLETE', 5.6, 'MEDIUM', 1.9, 9.2, 'A certain Red Hat script for sudo 1.7.2 on Red Hat Enterprise Linux (RHEL) 5 allows local users to overwrite arbitrary files via a symlink attack on the /var/tmp/nsswitch.conf.bak temporary file.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2010-0727', 4.9, '2.0', 'AV:L/AC:L/Au:N/C:N/I:N/A:C', 'LOCAL', 'LOW', 'NONE', False, 'UNCHANGED', 'NONE', 'NONE', 'COMPLETE', 4.9, 'MEDIUM', 3.9, 6.9," The gfs2_lock function in the Linux kernel before 2.6.34-rc1-next-20100312, and the gfs_lock function in the Linux kernel on Red Hat Enterprise Linux (RHEL) 5 and 6, does not properly remove POSIX locks on files that are setgid without group-execute permission, which allows local users to cause a denial of service (BUG and system crash) by locking a file on a (1) GFS or (2) GFS2 filesystem, and then changing this file's permissions.");
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2015-7833', 4.9, '2.0', 'AV:L/AC:L/Au:N/C:N/I:N/A:C', 'LOCAL', 'LOW', 'NONE', False, 'UNCHANGED', 'NONE', 'NONE', 'COMPLETE', 4.9, 'MEDIUM', 3.9, 6.9, 'The usbvision driver in the Linux kernel package 3.10.0-123.20.1.el7 through 3.10.0-229.14.1.el7 in Red Hat Enterprise Linux (RHEL) 7.1 allows physically proximate attackers to cause a denial of service (panic) via a nonzero bInterfaceNumber value in a USB device descriptor.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2020-7337', 6.7, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'HIGH', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 6.7, 'MEDIUM', 0.8, 5.9, 'Incorrect Permission Assignment for Critical Resource vulnerability in McAfee VirusScan Enterprise (VSE) prior to 8.8 Patch 16 allows local administrators to bypass local security protection through VSE not correctly integrating with Windows Defender Application Control via careful manipulation of the Code Integrity checks.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2009-5118', 9.3, '2.0', 'AV:N/AC:M/Au:N/C:C/I:C/A:C', 'NETWORK', 'MEDIUM', 'NONE', True, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 9.3, 'HIGH', 8.6, 10, 'Untrusted search path vulnerability in McAfee VirusScan Enterprise before 8.7i allows local users to gain privileges via a Trojan horse DLL in an unspecified directory, as demonstrated by scanning a document located on a remote share.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2007-2152', 7.9, '2.0', 'AV:A/AC:M/Au:N/C:C/I:C/A:C', 'ADJACENT_NETWORK', 'MEDIUM', 'NONE', True, 'CHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 7.9, 'HIGH', 5.5, 10, 'Buffer overflow in the On-Access Scanner in McAfee VirusScan Enterprise before 8.0i Patch 12 allows user-assisted remote attackers to execute arbitrary code via a long filename containing multi-byte (Unicode) characters.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-0101', 8.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'NETWORK', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 8.8, 'HIGH', 2.8, 5.9, 'A privilege escalation vulnerability was identified in Nessus versions 8.10.1 through 8.15.8 and 10.0.0 through 10.4.1. An authenticated attacker could potentially execute a specially crafted file to obtain root or NT AUTHORITY / SYSTEM privileges on the Nessus host.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2021-20135', 6.7, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'HIGH', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 6.7, 'MEDIUM', 0.8, 5.9, 'Nessus versions 8.15.2 and earlier were found to contain a local privilege escalation vulnerability which could allow an authenticated, local administrator to run specific executables on the Nessus Agent host. Tenable has included a fix for this issue in Nessus 10.0.0. The installation files can be obtained from the Tenable Downloads Portal (https://www.tenable.com/downloads/nessus).');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2020-5765', 5.4, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N', 'NETWORK', 'LOW', 'LOW', 'REQUIRED', 'CHANGED', 'LOW', 'LOW', 'NONE', 5.4, 'MEDIUM', 2.3, 2.7, 'Nessus 8.10.0 and earlier were found to contain a Stored XSS vulnerability due to improper validation of input during scan configuration. An authenticated remote attacker could potentially exploit this vulnerability to execute arbitrary code in a user\'s session. Tenable has implemented additional input validation mechanisms to correct this issue in Nessus 8.11.0.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2024-23675', 6.5, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N', 'NETWORK', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'NONE', 'HIGH', 'NONE', 6.5, 'MEDIUM', 2.8, 3.6, 'In Splunk Enterprise versions below 9.0.8 and 9.1.3, Splunk app key value store (KV Store) improperly handles permissions for users that use the REST application programming interface (API). This can potentially result in the deletion of KV Store collections.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2024-23676', 3.5, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N', 'NETWORK', 'LOW', 'LOW', 'REQUIRED', 'UNCHANGED', 'LOW', 'NONE', 'NONE', 3.5, 'LOW', 2.1, 1.4, 'In Splunk versions below 9.0.8 and 9.1.3, the “mrollup” SPL command lets a low-privileged user view metrics on an index that they do not have permission to view. This vulnerability requires user interaction from a high-privileged user to exploit.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-40593', 7.5, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'NETWORK', 'LOW', 'NONE', 'NONE', 'UNCHANGED', 'NONE', 'NONE', 'HIGH', 7.5, 'HIGH', 3.9, 3.6, 'In Splunk Enterprise versions lower than 9.0.6 and 8.2.12, a malicious actor can send a malformed security assertion markup language (SAML) request to the `/saml/acs` REST endpoint which can cause a denial of service through a crash or hang of the Splunk daemon.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-40592', 6.1, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N', 'NETWORK', 'LOW', 'NONE', 'REQUIRED', 'CHANGED', 'LOW', 'LOW', 'NONE', 6.1, 'MEDIUM', 2.8, 2.7, 'In Splunk Enterprise versions below 9.1.1, 9.0.6, and 8.2.12, an attacker can craft a special web request that can result in reflected cross-site scripting (XSS) on the “/app/search/table” web endpoint. Exploitation of this vulnerability can lead to the execution of arbitrary commands on the Splunk platform instance.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2013-1935', 5.7, '2.0', 'AV:A/AC:M/Au:N/C:N/I:N/A:C', 'ADJACENT_NETWORK', 'MEDIUM', 'NONE', False, 'UNCHANGED', 'NONE', 'NONE', 'COMPLETE', 5.7, 'MEDIUM', 5.5, 6.9, 'A certain Red Hat patch to the KVM subsystem in the kernel package before 2.6.32-358.11.1.el6 on Red Hat Enterprise Linux (RHEL) 6 does not properly implement the PV EOI feature, which allows guest OS users to cause a denial of service (host OS crash) by leveraging a time window during which interrupts are disabled but copy_to_user function calls are possible.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2013-2224', 6.9, '2.0', 'AV:L/AC:M/Au:N/C:C/I:C/A:C', 'LOCAL', 'MEDIUM', 'NONE', False, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 6.9, 'MEDIUM', 3.4, 10, 'A certain Red Hat patch for the Linux kernel 2.6.32 on Red Hat Enterprise Linux (RHEL) 6 allows local users to cause a denial of service (invalid free operation and system crash) or possibly gain privileges via a sendmsg system call with the IP_RETOPTS option, as demonstrated by hemlock.c.  NOTE: this vulnerability exists because of an incorrect fix for CVE-2012-3552.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2013-2188', 4.7, '2.0', 'AV:L/AC:M/Au:N/C:N/I:N/A:C', 'LOCAL', 'MEDIUM', 'NONE', False, 'UNCHANGED', 'NONE', 'NONE', 'COMPLETE', 4.7, 'MEDIUM', 3.4, 6.9, 'A certain Red Hat patch to the do_filp_open function in fs/namei.c in the kernel package before 2.6.32-358.11.1.el6 on Red Hat Enterprise Linux (RHEL) 6 does not properly handle failure to obtain write permissions, which allows local users to cause a denial of service (system crash) by leveraging access to a filesystem that is mounted read-only.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-47804', 8.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'NETWORK', 'LOW', 'NONE', 'REQUIRED', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 8.8, 'HIGH', 2.8, 5.9, 'Apache OpenOffice documents can contain links that call internal macros with arbitrary arguments. Several URI Schemes are defined for this purpose.Links can be activated by clicks, or by automatic document events.The execution of such links must be subject to user approval.In the affected versions of OpenOffice, approval for certain links is not requested; when activated, such links could therefore result in arbitrary script execution.This is a corner case of CVE-2022-47502.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2022-37401', 8.8, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H', 'NETWORK', 'LOW', 'LOW', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 8.8, 'HIGH', 2.8, 5.9," Apache OpenOffice supports the storage of passwords for web connections in the user's configuration database. The stored passwords are encrypted with a single master key provided by the user. A flaw in OpenOffice existed where master key was poorly encoded resulting in weakening its entropy from 128 to 43 bits making the stored passwords vulnerable to a brute force attack if an attacker has access to the users stored config. This issue affects: Apache OpenOffice versions prior to 4.1.13. Reference: CVE-2022-26307 - LibreOffice");
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2021-33035', 7.8, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'NONE', 'REQUIRED', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 7.8, 'HIGH', 1.8, 5.9, 'Apache OpenOffice opens dBase/DBF documents and shows the contents as spreadsheets. DBF are database files with data organized in fields. When reading DBF data the size of certain fields is not checked: the data is just copied into local variables. A carefully crafted document could overflow the allocated space, leading to the execution of arbitrary code by altering the contents of the program stack. This issue affects Apache OpenOffice up to and including version 4.1.10');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2020-13958', 7.8, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'NONE', 'REQUIRED', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 7.8, 'HIGH', 1.8, 5.9, 'A vulnerability in Apache OpenOffice scripting events allows an attacker to construct documents containing hyperlinks pointing to an executable on the target users file system. These hyperlinks can be triggered unconditionally. In fixed versions no internal protocol may be called from the document event handler and other hyperlinks require a control-click.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2017-12607', 7.8, '3.1', 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H', 'LOCAL', 'LOW', 'NONE', 'REQUIRED', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 7.8, 'HIGH', 1.8, 5.9, 'A vulnerability in OpenOffice\'s PPT file parser before 4.1.4, and specifically in PPTStyleSheet, allows attackers to craft malicious documents that cause denial of service (memory corruption and application crash) potentially resulting in arbitrary code execution.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-0323', 6.6, '2.0', 'AV:L/AC:L/Au:N/C:C/I:N/A:C', 'LOCAL', 'LOW', 'NONE', False, 'UNCHANGED', 'COMPLETE', 'NONE', 'COMPLETE', 6.6, 'MEDIUM', 3.9, 9.2, 'win32k.sys in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to obtain sensitive information from kernel memory or cause a denial of service (system hang) via a crafted application," aka Win32k Information Disclosure Vulnerability.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-0315', 6.9, '2.0', 'AV:L/AC:M/Au:N/C:C/I:C/A:C', 'LOCAL', 'MEDIUM', 'NONE', True, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 6.9, 'MEDIUM', 3.4, 10, 'Untrusted search path vulnerability in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows local users to gain privileges via a Trojan horse cmd.exe file in the current working directory, as demonstrated by a directory that contains a .bat or .cmd file," aka Windows File Handling Vulnerability.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2013-5058', 6.9, '2.0', 'AV:L/AC:M/Au:N/C:C/I:C/A:C', 'LOCAL', 'MEDIUM', 'NONE', True, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 6.9, 'MEDIUM', 3.4, 10, 'Integer overflow in the kernel-mode drivers in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows local users to gain privileges via a crafted application, aka Win32k Integer Overflow Vulnerability.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2013-5056', 9.3, '2.0', 'AV:N/AC:M/Au:N/C:C/I:C/A:C', 'NETWORK', 'MEDIUM', 'NONE', True, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 9.3, 'HIGH', 8.6, 10, 'Use-after-free vulnerability in the Scripting Runtime Object Library in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, Windows Server 2012 Gold and R2, and Windows RT Gold and 8.1 allows remote attackers to execute arbitrary code or cause a denial of service (memory corruption) via a crafted web site that is visited with Internet Explorer," aka Use-After-Free Vulnerability in Microsoft Scripting Runtime Object Library.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2017-8543', 9.8, '3.0', 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'NETWORK', 'LOW', 'NONE', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'HIGH', 9.8, 'CRITICAL', 3.9, 5.9, 'Microsoft Windows XP SP3, Windows XP x64 XP2, Windows Server 2003 SP2, Windows Vista, Windows 7 SP1, Windows Server 2008 SP2 and R2 SP1, Windows 8, Windows 8.1 and Windows RT 8.1, Windows Server 2012 and R2, Windows 10 Gold,1511,1607, and 1703, and Windows Server 2016 allow an attacker to take control of the affected system when Windows Search fails to handle objects in memory," aka Windows Search Remote Code Execution Vulnerability.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2014-0301', 9.3, '2.0', 'AV:N/AC:M/Au:N/C:C/I:C/A:C', 'NETWORK', 'MEDIUM', 'NONE', True, 'UNCHANGED', 'COMPLETE', 'COMPLETE', 'COMPLETE', 9.3, 'HIGH', 8.6, 10, 'Double free vulnerability in qedit.dll in DirectShow in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via a crafted JPEG image," aka DirectShow Memory Corruption Vulnerability.');
INSERT INTO VULNERABILITIES_DATA VALUES('CVE-2023-20269', 9.1, '3.1', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N', 'NETWORK', 'LOW', 'NONE', 'NONE', 'UNCHANGED', 'HIGH', 'HIGH', 'NONE', 9.1, 'CRITICAL', 3.9, 5.2, 'Double free vulnerability in qedit.dll in DirectShow in Microsoft Windows XP SP2 and SP3, Windows Server 2003 SP2, Windows Vista SP2, Windows Server 2008 SP2 and R2 SP1, Windows 7 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via a crafted JPEG image," aka DirectShow Memory Corruption Vulnerability.');


# INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(category_id, category_name);
INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(null, "boundary defense and system administrator rack");
INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(null, "bulk data storage rack");
INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(null, "company laptops");
INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(null, "company workstations");
INSERT INTO INFRASTRUCTURE_CATEGORIES VALUES(null, "server rack");

# INSERT INTO INFRASTRUCTURE_NODES VALUES(infra_id, serial_number, infra_make, infra_model, description, category_id);
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "CS23XZ8910F", "Cisco", "4125 NGFW", "Next Generation Firewall (NGFW) with Intrusion Protection Systems (IPS), rack mountable, 1U", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "MS42532MX102", "Cisco", "MS425-32", "Meraki Layer 3 Switch (Router)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "CAT2960X1903C", "Cisco", "Catalyst 2960-X", "Layer 2 Gigabit Ethernet Network Switch", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "TL0018KB457", "Tripp Lite", "B030-008-17-IP", "Tripp Lite 8-Port Rackmount Console HDMI KVM Switch 17 LCD IP Remote Access B030-008-17-IP, Rack Mounted Monitor, Keyboard, and Touchpad", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "DE075PRXY920", "Dell", "PowerEdge R750", "Rack Server (2U, Intel C620 series chipset, up to two 3rd Generation Intel Xeon processors with up to 40 cores per processor)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "PVME5024DN82", "Dell", "PowerVault ME5024", "Storage Area Network (SAN)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "TL48PANELZ108", "Tripp Lite", "N052-048-1U", "48-Port Patch Panel (1U Rack-Mount, 558B, Cat6/Cat5, RJ45)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "APC3KVM9142U", "APC", "SMT3000RM2UC", "Uninterruptible Power Supply (3kVA, 2U rackmount, Smart-UPS)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'boundary defense and system administrator rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "CAT2960XZQ450", "Cisco", "Catalyst 2960-X", "Layer 2 Gigabit Ethernet Network Switch", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'bulk data storage rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "PVME5024GHT66", "Dell", "PowerVault ME5024", "Storage Area Network (SAN)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'bulk data storage rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "TL48PATCH39X7", "Tripp Lite", "N052-048-1U", "48-Port Patch Panel (1U Rack-Mount, 558B, Cat6/Cat5, RJ45)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'bulk data storage rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "MS42532LZT341", "Cisco", "MS425-32", "Cisco Meraki Layer 3 Switch (32 ports, 10 Gb)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'bulk data storage rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "APCUPS5009YY", "APC", "SMT3000RM2UC", "Uninterruptible Power Supply (3kVA, 2U rackmount, Smart-UPS)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'bulk data storage rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "DE7330LAT001", "Dell", "7330", "Rugged Latitude Extreme Laptop", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'company laptops'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "GAT231ZTB902", "Gator", "None", "ATA TSA Molded Laptop Travel Case (Hard Shell, Exterior Dimensions: 19.38in W x 14.5in D x 9.75in H)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'company laptops'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "DEP5820KYL329", "Dell", "Precision 5820", "Computer Tower with Keyboard and Mouse", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'company workstations'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "SAM24LCD7820L", "Samsung", "S24C450DL", "24in Widescreen LCD Display", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'company workstations'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "CAT2960XX0341C", "Cisco", "Catalyst 2960-X", "Layer 2 Gigabit Ethernet Network Switch", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "DEPR750BBX019", "Dell", "PowerEdge R750", "Rack Server (2U, Intel C620 series chipset, up to two 3rd Generation Intel Xeon processors with up to 40 cores per processor)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "TL48PANELX0097", "Tripp Lite", "N052-048-1U", "48-Port Patch Panel (1U Rack-Mount, 558B, Cat6/Cat5, RJ45)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "MS42532NGX492", "Cisco", "MS425-32", "Cisco Meraki Layer 3 Switch (32 ports, 10 Gb)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "PVME5024RV234", "Dell", "PowerVault ME5024", "Storage Area Network (SAN)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));
INSERT INTO INFRASTRUCTURE_NODES VALUES(null, "APC3KUP2X93D", "APC", "SMT3000RM2UC", "Uninterruptible Power Supply (3kVA, 2U rackmount, Smart-UPS)", (SELECT category_id FROM INFRASTRUCTURE_CATEGORIES WHERE category_name = 'server rack'));

# INSERT INTO ENDPOINT_NODE VALUES(endpoint_id, endpoint_name);
INSERT INTO ENDPOINT_NODES VALUES(null, "System Administrator Terminal");
INSERT INTO ENDPOINT_NODES VALUES(null, "Virtualization Manager Server");
INSERT INTO ENDPOINT_NODES VALUES(null, "Virtualization Manager SAN Archive");
INSERT INTO ENDPOINT_NODES VALUES(null, "Cybersecurity Capability & Tools Server");
INSERT INTO ENDPOINT_NODES VALUES(null, "Cybersecurity Capability & Tools SAN Archive");
INSERT INTO ENDPOINT_NODES VALUES(null, "Cybersecurity Capability & Tools SAN Archive Backup");
INSERT INTO ENDPOINT_NODES VALUES(null, "Audit Log Server");
INSERT INTO ENDPOINT_NODES VALUES(null, "Audit Log SAN Archive");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #1 (SR1)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #2 (SR2)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #3 (SR3)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #4 (SR4)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #5 (SR5)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #6 (SR6)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #7 (SR7)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #8 (SR8)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #9 (SR9)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #10 (SR10)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #11 (SR11)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Server Rack, Server #12 (SR12)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN 1");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN Archive 1");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN Archive 1 Backup");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN 2");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN Archive 2");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN Archive 2 Backup");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production SAN 3");
INSERT INTO ENDPOINT_NODES VALUES(null, "Test SAN");
INSERT INTO ENDPOINT_NODES VALUES(null, "Test SAN Archive");
INSERT INTO ENDPOINT_NODES VALUES(null, "Test SAN Archive Backup");
INSERT INTO ENDPOINT_NODES VALUES(null, "Company Management SAN");
INSERT INTO ENDPOINT_NODES VALUES(null, "Company Management SAN Archive");
INSERT INTO ENDPOINT_NODES VALUES(null, "Company Management SAN Archive Backup");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production (Workstation 1)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production (Workstation 2)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production (Workstation 3)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Engineering & Production (Workstation 4)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Company Management (Workstation 5)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Company Management (Workstation 6)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Test Engineering (Laptop 1)");
INSERT INTO ENDPOINT_NODES VALUES(null, "Test Engineering (Laptop 2)");
INSERT INTO ENDPOINT_NODES VALUES(null,  "Layer 3 Switch");
INSERT INTO ENDPOINT_NODES VALUES(null,  "Layer 2 Switch");

# INSERT INTO SOFTWARE_FIRMWARE VALUES(software_id, software_make, software_name, software_version, endpoint_id);
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Cisco", "FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software", "6.6.7");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Cisco", "Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)", "9/23/2014");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Cisco", "Catalyst 2960-X IOS", "IOS 15.2(1)E");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "RedHat Enterprise Linux (RHEL)", "RHEL 5.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "RedHat Enterprise Linux (RHEL)", "RHEL 7.1");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "McAfee", "VirusScan Enterprise", "2");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Tenable", "Nessus Vulnerability Scanner", "8.10.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Splunk", "Enterprise Security Information and Event Manager (SIEM)", "8.6");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "RedHat Enterprise Linux", "RHEL 6.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Cisco", "Catalyst 2960-X", "IOS 15.2(1)E");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "Red Hat Enterprise Linux (RHEL)", "RHEL 5.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "OpenOffice", "Apache OpenOffice (Open Source)", "4.1.1.4");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "Red Hat Enterprise Linux (RHEL)", "RHEL 6.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "RedHat", "RedHat Enterprise Linux", "RHEL 5.0");
INSERT INTO SOFTWARE_FIRMWARE VALUES(null, "Microsoft", "Windows Server 2008 Service Pack 2", "Windows Server 2008 SP2");

# INSERT INTO SYSTEM_SCORING VALUES(apt_group, score_name, score, reasoning, remediations);
INSERT INTO SYSTEM_SCORING VALUES("Dragonfly", "Physical", 0.40, "The company's physical security measures are inadequate, with several vulnerabilities identified. The facility layout has potential issues that could impact cyber resiliency, and there are no physical access controls for some rooms. The equipment room door is often left unlocked, and the production floor door has a key lock, but the key is not used. The alarm system only monitors the main entrance and production floor doors.", JSON_ARRAY("Ensure that all doors, including the equipment room door, are locked when not in use, and that keys are managed securely.", "Implement physical access controls, such as card readers or biometric authentication, for all rooms containing sensitive equipment or data.", "Expand the alarm system to monitor all doors, including those leading to sensitive areas, and ensure that it is regularly tested and maintained."));
INSERT INTO SYSTEM_SCORING VALUES("Dragonfly", "Personnel", 0.30, "The IT staff has a mix of training and experience, but most staff members lack recent IT and cybersecurity certifications. One staff member is overworked and responsible for the majority of cybersecurity tasks. The company's personnel policies and procedures are not well-defined, and there is no clear incident response plan.", JSON_ARRAY("Provide regular training and certification opportunities for IT staff to ensure they have the necessary skills and knowledge to perform their duties effectively.", "Develop and implement clear personnel policies and procedures, including an incident response plan, to ensure that all staff members know their roles and responsibilities.", "Hire additional IT staff to support the overworked staff member and ensure that cybersecurity tasks are distributed fairly."));
INSERT INTO SYSTEM_SCORING VALUES("Dragonfly", "Policies", 0.30, "The company has some policies and procedures in place, such as the user account processes and monitoring procedures, but they are not well-defined or consistently enforced. The company's cybersecurity policy and procedures are not clearly documented, and there is no clear incident response plan.", JSON_ARRAY("Establish a regular review and update process for all policies and procedures to ensure they remain relevant and effective.", "Review and update the company's user account processes and monitoring procedures to ensure they are consistent with industry best practices.", "Develop and document clear cybersecurity policies and procedures, including an incident response plan, to ensure that all staff members know their roles and responsibilities."));

# INSERT INTO FUNCTION_DEFINITIONS VALUES(function_number, function_name, work_area, criticality_value);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F1", "Data Input/Processing", "Engineering & Production", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F2", "Data Storage", "Engineering & Production", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F3", "Data Archiving/Long-term Storage", "Engineering & Production", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F4", "Testing/Validation", "Test Engineering", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F5", "Security Operations/Monitoring", "IT & Cybersecurity", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F6", "Incident Response", "IT & Cybersecurity", 3);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F7", "Backup Management", "Engineering & Production", 2);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F8", "File/Database Management", "Test Engineering", 2);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F9", "Analytics/Reporting", "Test Engineering", 2);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F10", "Management/Administration", "Company Management", 2);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F11", "Specialized Engineering", "Engineering & Production", 1);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F12", "Access Control", "Test Engineering", 1);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F13", "Policy Enforcement", "Company Management", 1);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F14", "Redundancy/Failover", "Company Management", 1);
INSERT INTO FUNCTION_DEFINITIONS VALUES("F15", "Executive Management", "Company Management", 1);

# INSERT INTO FUNCTION_MAPPING VALUES(endpoint_id, function_number);
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'System Administrator Terminal'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'System Administrator Terminal'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager Server'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager Server'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager Server'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager SAN Archive'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager SAN Archive'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive Backup'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive Backup'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log Server'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log Server'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log SAN Archive'), "F5");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log SAN Archive'), "F6");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #1 (SR1)'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #1 (SR1)'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #2 (SR2)'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #2 (SR2)'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #3 (SR3)'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #4 (SR4)'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #4 (SR4)'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #4 (SR4)'), "F9");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #5 (SR5)'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #6 (SR6)'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #6 (SR6)'), "F13");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #7 (SR7)'), "F12");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #7 (SR7)'), "F14");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #8 (SR8)'), "F15");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #9 (SR9)'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #9 (SR9)'), "F9");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #9 (SR9)'), "F12");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #10 (SR10)'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #11 (SR11)'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #12 (SR12)'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 1'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 1'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 1'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1 Backup'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 2'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 2'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 2'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2 Backup'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 3'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN'), "F9");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive'), "F9");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive Backup'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN'), "F13");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN'), "F14");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN'), "F15");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive'), "F13");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive'), "F14");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive'), "F15");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive Backup'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive Backup'), "F13");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive Backup'), "F14");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive Backup'), "F15");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 1)'), "F1");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 1)'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 2)'), "F3");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 3)'), "F2");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 3)'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 4)'), "F7");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 4)'), "F11");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 1)'), "F4");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 2)'), "F8");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 2)'), "F9");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), "F10");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), "F13");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), "F14");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), "F15");
INSERT INTO FUNCTION_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 6)'), "F13");
    
# INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES(endpoint_id, software_id);
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'System Administrator Terminal'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Layer 3 Switch'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)' AND software_version = '9/23/2014'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Layer 2 Switch'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X IOS' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'McAfee' AND software_name = 'VirusScan Enterprise' AND software_version = '2'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Tenable' AND software_name = 'Nessus Vulnerability Scanner' AND software_version = '8.10.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Splunk' AND software_name = 'Enterprise Security Information and Event Manager (SIEM)' AND software_version = '8.6'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log Server'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Virtualization Manager SAN Archive'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Audit Log SAN Archive'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Layer 2 Switch'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 1 Backup'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN Archive 2 Backup'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN Archive Backup'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Cybersecurity Capability & Tools SAN Archive Backup'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN Archive Backup'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 1)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 1)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 2)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test Engineering (Laptop 2)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 1)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 1)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 2)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 2)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 3)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 3)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 4)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production (Workstation 4)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 5)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 6)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'Red Hat Enterprise Linux (RHEL)' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management (Workstation 6)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #1 (SR1)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #2 (SR2)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #3 (SR3)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #4 (SR4)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #5 (SR5)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #6 (SR6)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #7 (SR7)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #8 (SR8)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #9 (SR9)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #10 (SR10)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #11 (SR11)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Server Rack, Server #12 (SR12)'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 1'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 2'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Engineering & Production SAN 3'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Test SAN'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO SOFTWARE_FIRMWARE_MAPPING VALUES((SELECT endpoint_id FROM ENDPOINT_NODES WHERE endpoint_name = 'Company Management SAN'), (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));

# INSERT INTO VULNERABILITY_INSTANCES VALUES(cve_number, software_id);
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20256", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20247", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20200", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20095", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20015", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-20934", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'FirePower 4125 Next Generation Firewall with Firepower Threat Defense (FTD) Software' AND software_version = '6.6.7'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2018-0284", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)' AND software_version = '9/23/2014'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-7999", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)' AND software_version = '9/23/2014'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-7993", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)' AND software_version = '9/23/2014'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-7994", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Meraki MS425-32 Layer 3 Switch (firmware 2014-09-23)' AND software_version = '9/23/2014'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2016-6473", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2017-6606", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2017-3803", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2016-1425", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Cisco' AND software_name = 'Catalyst 2960-X' AND software_version = 'IOS 15.2(1)E'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2012-2697", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2012-3440", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2010-0727", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2015-7833", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux (RHEL)' AND software_version = 'RHEL 7.1'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2020-7337", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'McAfee' AND software_name = 'VirusScan Enterprise' AND software_version = '2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2009-5118", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'McAfee' AND software_name = 'VirusScan Enterprise' AND software_version = '2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2007-2152", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'McAfee' AND software_name = 'VirusScan Enterprise' AND software_version = '2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-0101", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Tenable' AND software_name = 'Nessus Vulnerability Scanner' AND software_version = '8.10.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2021-20135", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Tenable' AND software_name = 'Nessus Vulnerability Scanner' AND software_version = '8.10.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2020-5765", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Tenable' AND software_name = 'Nessus Vulnerability Scanner' AND software_version = '8.10.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2024-23675", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Splunk' AND software_name = 'Enterprise Security Information and Event Manager (SIEM)' AND software_version = '8.6'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2024-23676", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Splunk' AND software_name = 'Enterprise Security Information and Event Manager (SIEM)' AND software_version = '8.6'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-40593", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Splunk' AND software_name = 'Enterprise Security Information and Event Manager (SIEM)' AND software_version = '8.6'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-40592", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Splunk' AND software_name = 'Enterprise Security Information and Event Manager (SIEM)' AND software_version = '8.6'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2013-1935", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2013-2224", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2013-2188", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 6.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2012-2697", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2012-3440", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2010-0727", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'RedHat' AND software_name = 'RedHat Enterprise Linux' AND software_version = 'RHEL 5.0'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2023-47804", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2022-37401", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2021-33035", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2020-13958", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2017-12607", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'OpenOffice' AND software_name = 'Apache OpenOffice (Open Source)' AND software_version = '4.1.1.4'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2017-8543", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-0301", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-0323", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2014-0315", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2013-5058", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));
INSERT INTO VULNERABILITY_INSTANCES VALUES("CVE-2013-5056", (SELECT software_id FROM SOFTWARE_FIRMWARE WHERE software_make = 'Microsoft' AND software_name = 'Windows Server 2008 Service Pack 2' AND software_version = 'Windows Server 2008 SP2'));

# INSERT INTO APT_CVE_SCORING(cve_number, apt_group, score, reasoning);
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20269", "Dragonfly", "0.68", "Dragonfly's focus on targeting critical infrastructure sectors and their use of supply chain attacks might lead them to exploit this vulnerability, especially since it affects network security devices, which could provide a foothold in their desired sectors; however, the requirement for valid credentials, including a second factor if MFA is configured, might reduce the appeal of this vulnerability to the group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20256", "Dragonfly", "0.72", "Given Dragonfly's focus on targeting critical infrastructure sectors and their use of supply chain attacks, the likelihood of them exploiting this vulnerability is high. However, the vulnerability requires a specific configuration to be exploited, which might limit its appeal to the group, hence a score below 1.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20247", "Dragonfly", "0.68", "Given Dragonfly's focus on supply chain attacks and targeting critical infrastructure, the likelihood of exploiting a Cisco ASA/FTD vulnerability is moderate, as these devices are commonly used in such sectors. However, the vulnerability requires authentication, which might not align with Dragonfly's typical tactics of initial access through supply chain attacks or other means.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20200", "Dragonfly", "0.62", "Dragonfly's focus on critical infrastructure sectors and supply chain attacks increases the likelihood of exploiting this vulnerability, as it affects network management services in sectors like defense and energy. However, the requirement for authentication or knowledge of SNMP community strings reduces the likelihood of exploitation, as Dragonfly's typical tactics involve more stealthy and opportunistic approaches.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20095", "Dragonfly", "0.72", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors increases the likelihood of exploiting this vulnerability, given the potential impact on defense and energy sectors. However, the vulnerability's relatively simple denial-of-service nature and lack of clear lateral movement or data exfiltration potential may limit its appeal to a sophisticated group like Dragonfly.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20015", "Dragonfly", "0.72", "Dragonfly's focus on critical infrastructure sectors and use of supply chain attacks align with the potential impact of exploiting a vulnerability in network security appliances and data center equipment, making them likely to exploit this vulnerability if they have the necessary access. However, the vulnerability requires local authentication, which may limit its appeal to a group that often relies on more remote and stealthy tactics.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-20934", "Dragonfly", "0.20", "The vulnerability is an Android-specific local escalation of privilege issue, which is unlikely to be relevant to Dragonfly's typical targets of critical infrastructure sectors. Dragonfly's TTPs typically involve supply chain attacks, making it less likely they would focus on exploiting this specific Android vulnerability.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2018-0284", "Dragonfly", "0.67", "Dragonfly's focus on critical infrastructure sectors and use of supply chain attacks make it plausible they would exploit a vulnerability allowing them to establish an interactive session with elevated privileges. However, the requirement for an authenticated attacker and the relatively old age of the vulnerability (2018) slightly reduce the likelihood of exploitation.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-7999", "Dragonfly", "0.23", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors does not directly align with exploiting a 9-year-old firmware vulnerability in Cisco-Meraki devices, and the requirement for remote authentication reduces the vulnerability's appeal for their typical tactics. However, it's still possible they might leverage this vulnerability in a specific, targeted operation.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-7993", "Dragonfly", "0.67", "Dragonfly's focus on critical infrastructure sectors, including energy and aviation, aligns with the potential targets of Cisco-Meraki devices, making exploitation plausible. However, the vulnerability's age (2014) and the group's preference for supply chain attacks may decrease the likelihood of exploiting this specific vulnerability.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-7994", "Dragonfly", "0.30", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors suggests they may not prioritize exploiting a 9-year-old vulnerability in Cisco-Meraki devices, which may not be prevalent in their target sectors; however, their technical sophistication and adaptability cannot be entirely ruled out.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2016-6473", "Dragonfly", "0.40", "Dragonfly's primary focus on supply chain attacks and targeting critical infrastructure sectors such as defense, energy, and aviation, suggests they might not prioritize exploiting a 7-year-old network vulnerability like CVE-2016-6473, which is relatively old and has likely been patched in most environments, reducing its value as a viable attack vector. However, the vulnerability's impact on network availability and potential for lateral movement might still make it an attractive option for Dragonfly, albeit a less preferred one.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2017-6606", "Dragonfly", "0.43", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors does not directly align with exploiting a publicly disclosed vulnerability in Cisco IOS XE Software, which may not be a typical entry point for their operations. However, their interest in critical infrastructure sectors such as energy and aviation may lead them to explore vulnerabilities in network equipment, making exploitation possible but not highly likely.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2017-3803", "Dragonfly", "0.22", "Dragonfly's primary tactics involve targeting high-value critical infrastructure through supply chain attacks, often using sophisticated social engineering and zero-day exploits. Given the relatively low-impact partial denial of service nature of this vulnerability and the requirement for adjacency to the vulnerable switch, it's unlikely to align with Dragonfly's typical objectives and methods.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2016-1425", "Dragonfly", "0.40", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors does not strongly align with exploiting a network device vulnerability like CVE-2016-1425, which is more related to network disruption. However, their general interest in disrupting critical infrastructure sectors gives them some motivation to exploit this vulnerability.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2012-2697", "Dragonfly", "0.14", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors suggests they prioritize high-impact exploits, whereas CVE-2012-2697 is a relatively low-severity, local DoS vulnerability with limited potential for lateral movement or significant disruption. Additionally, the vulnerability's age and limited scope make it an unlikely candidate for exploitation by a sophisticated group like Dragonfly.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2012-3440", "Dragonfly", "0.20", "The vulnerability is an older, local privilege escalation issue that may not be as appealing to Dragonfly, who primarily targets high-impact supply chain attacks, and may not be relevant to their typical TTPs. Additionally, the vulnerability requires an existing foothold on a RHEL 5 system, which may not align with their typical attack vectors.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2010-0727", "Dragonfly", "0.15", "Dragonfly's TTPs focus on supply chain attacks and targeting critical infrastructure sectors, but there is no indication they specifically target Linux kernel vulnerabilities or exploit local denial-of-service bugs, making it unlikely they would prioritize CVE-2010-0727. The vulnerability's age and relatively low impact also suggest it's not a prime target for this APT group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2015-7833", "Dragonfly", "0.17", "Dragonfly's primary focus on supply chain attacks and targeting critical infrastructure sectors makes it unlikely for them to exploit a relatively old Linux kernel vulnerability that requires physical proximity to the target system. The vulnerability's local exploitation vector and lack of relevance to their typical TTPs further reduce the likelihood of exploitation.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2020-7337", "Dragonfly", "0.72", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors aligns with the potential for exploiting vulnerabilities in security software like McAfee VirusScan Enterprise, making it a plausible target. However, the vulnerability requires local administrator access, which might limit its appeal to Dragonfly, given their preference for more stealthy and scalable exploitation methods.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2009-5118", "Dragonfly", "0.30", "Dragonfly's primary focus on supply chain attacks and targeting critical infrastructure sectors using more sophisticated methods makes it less likely for them to exploit a 14-year-old vulnerability like CVE-2009-5118, which requires local access and may not be as effective in their typical attack scenarios. However, the group's adaptability and willingness to use various tactics means they may still consider using this vulnerability in specific situations.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2007-2152", "Dragonfly", "0.20", "The vulnerability is an older, user-assisted remote attack that requires a specific version of McAfee VirusScan Enterprise, making it less likely to be exploited by Dragonfly, who tend to use more sophisticated supply chain attacks. Additionally, the group's focus on critical infrastructure sectors may not align with exploiting a relatively outdated vulnerability in an antivirus software.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-0101", "Dragonfly", "0.42", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors does not directly align with exploiting a vulnerability in a specific network scanning tool like Nessus, making it less likely for them to prioritize this vulnerability. However, their interest in escalating privileges in critical systems keeps the possibility open, albeit with relatively low probability.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2021-20135", "Dragonfly", "0.42", "Dragonfly's typical modus operandi involves targeting critical infrastructure sectors through supply chain attacks, and their tactics often rely on exploiting vulnerabilities in software used by their targets. While Nessus is a vulnerability scanner used in many industries, the specific vulnerability in question (CVE-2021-20135) is a local privilege escalation issue that may not be directly relevant to Dragonfly's typical attack vectors.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2020-5765", "Dragonfly", "0.62", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors increases the likelihood of exploiting a vulnerability in a widely-used security scanner like Nessus, but the requirement for authentication and the relatively low-impact nature of a stored XSS vulnerability make it less desirable compared to more impactful exploits.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2024-23675", "Dragonfly", "0.38", "Dragonfly's primary focus on supply chain attacks and targeting defense, energy, and aviation sectors may not directly align with exploiting a vulnerability in a logging and monitoring tool like Splunk, making it less likely for them to prioritize this vulnerability. However, their adaptability and past exploitation of various vulnerabilities still leave a possibility for them to leverage this vulnerability in a targeted attack.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2024-23676", "Dragonfly", "0.22", "Dragonfly's typical TTPs involve supply chain attacks, which don't align closely with exploiting a vulnerability like CVE-2024-23676 that requires user interaction and specific access to Splunk instances. Given their focus on high-impact sectors and tactics, exploiting this vulnerability seems unlikely to be a priority for the group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-40593", "Dragonfly", "0.30", "Dragonfly's focus on supply chain attacks and critical infrastructure sectors doesn't directly align with the exploitation of a denial-of-service vulnerability in Splunk Enterprise, a security monitoring platform. While possible, it's unlikely they would prioritize this vulnerability over others that offer more strategic value or direct access to their target sectors.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-40592", "Dragonfly", "0.60", "Dragonfly's focus on critical infrastructure sectors and supply chain attacks may lead them to exploit vulnerabilities in widely used enterprise software like Splunk, but their typical modus operandi involves more targeted and sophisticated attacks, making it less likely for them to prioritize a reflected XSS vulnerability. However, the potential for arbitrary command execution on a critical platform like Splunk might still make it an attractive target, hence the moderate score.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2013-1935", "Dragonfly", "0.30", "The likelihood of Dragonfly exploiting this vulnerability is low as it is a relatively old vulnerability (CVE-2013-1935) and the group's TTPs focus more on supply chain attacks, which may not align with exploiting a specific kernel vulnerability. However, given their targeting of critical infrastructure sectors, it's possible they may still exploit it if they can leverage it to gain access to a specific system or network.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2013-2224", "Dragonfly", "0.20", "Although Dragonfly is known to target critical infrastructure, the vulnerability in question is an old local privilege escalation vulnerability on a specific Linux kernel version, and their typical modus operandi involves supply chain attacks rather than exploiting old local vulnerabilities, making it less likely for them to exploit this vulnerability. Additionally, the vulnerability's requirement for local access and specific system configuration reduces its appeal for a group that typically conducts targeted attacks on a larger scale.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2013-2188", "Dragonfly", "0.17", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors does not align with the exploitation of a 10-year-old local privilege escalation vulnerability in a Linux kernel, making it unlikely for them to exploit this vulnerability. Additionally, the vulnerability requires local access to a read-only filesystem, which limits its utility for a group that typically engages in more sophisticated and strategic attacks.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2023-47804", "Dragonfly", "0.62", "I've assigned a moderate likelihood score as Dragonfly's TTPs involve supply chain attacks and exploiting vulnerabilities in software used by their targeted sectors. While CVE-2023-47804 affects Apache OpenOffice, which might be used by some organizations in critical infrastructure sectors, it is not a typical attack vector for Dragonfly, and the vulnerability's complexity and specific requirements might limit its appeal to the group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2022-37401", "Dragonfly", "0.30", "Dragonfly's primary focus on critical infrastructure sectors and supply chain attacks suggest that they may not prioritize exploiting a vulnerability in Apache OpenOffice, which is not typically a critical component in their target sectors. However, the group's use of various tactics and methods to gain access to sensitive information makes it possible that they might still exploit this vulnerability as a secondary or opportunistic attack vector.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2021-33035", "Dragonfly", "0.30", "The likelihood of Dragonfly exploiting this vulnerability is low due to their focus on supply chain attacks and targeting critical infrastructure sectors, which does not typically involve exploiting vulnerabilities in office software like Apache OpenOffice. Additionally, the vulnerability's requirement of a 'carefully crafted document' to overflow the allocated space suggests a relatively complex and targeted attack, which may not align with Dragonfly's typical tactics.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2020-13958", "Dragonfly", "0.42", "The likelihood of Dragonfly exploiting CVE-2020-13958 is moderate to low due to the vulnerability's reliance on a specific application (Apache OpenOffice) and the group's historical focus on supply chain attacks targeting critical infrastructure sectors. While it's possible Dragonfly could adapt this vulnerability to suit their needs, their typical TTPs and exploitation methods make it less likely they would prioritize this specific vulnerability.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2017-12607", "Dragonfly", "0.30", "Given Dragonfly's focus on supply chain attacks targeting critical infrastructure sectors, and their typical exploitation methods, it is unlikely that they would exploit a relatively old vulnerability in OpenOffice's PPT file parser, which doesn't seem to align with their typical tactics. The vulnerability's age and limited scope also decrease the likelihood of Dragonfly using it for their attacks.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2017-8543", "Dragonfly", "0.40", "Although Dragonfly is known for using supply chain attacks, which can involve exploiting vulnerabilities in software, the vulnerability in question (CVE-2017-8543) is specifically related to Windows Search and may not be directly relevant to their typical targets in critical infrastructure sectors. Additionally, the vulnerability is over 5 years old, and it is likely that many organizations have already patched it, reducing its attractiveness to the APT group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-0301", "Dragonfly", "0.40", "Dragonfly's typical focus on supply chain attacks and targeting critical infrastructure sectors makes it less likely for them to exploit a relatively old vulnerability in a Windows component like DirectShow, but it's still possible they might use it in a broader phishing or spear-phishing campaign to gain initial access.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-0323", "Dragonfly", "0.23", "Dragonfly's primary focus on supply chain attacks and targeting critical infrastructure sectors suggests they may not prioritize exploiting a local vulnerability like CVE-2014-0323, which requires an attacker to already have a presence on the system. Additionally, the vulnerability's age and potential for detection due to system hangs or crashes may further reduce its appeal to this APT group.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2014-0315", "Dragonfly", "0.17", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors suggests they prefer more sophisticated and stealthy methods, making the exploitation of a relatively old and local vulnerability like CVE-2014-0315 less likely. Additionally, the vulnerability requires a Trojan horse cmd.exe file to be present in the current working directory, which may not align with Dragonfly's typical modus operandi.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2013-5058", "Dragonfly", "0.20", "Dragonfly's focus on supply chain attacks and targeting critical infrastructure sectors suggests that they may not prioritize exploiting local privilege escalation vulnerabilities like CVE-2013-5058, which would require them to already have a foothold on the target system. Additionally, the vulnerability's age and the fact that it has likely been patched in most environments further reduces the likelihood of Dragonfly exploiting it.");
INSERT INTO APT_CVE_SCORING VALUES("CVE-2013-5056", "Dragonfly", "0.21", "Given Dragonfly's focus on supply chain attacks and targeting critical infrastructure, a client-side vulnerability like CVE-2013-5056, which requires user interaction with a crafted website, is less likely to align with their typical TTPs. Additionally, the age of the vulnerability (CVE-2013-5056) makes it less likely to be exploited by a sophisticated group like Dragonfly, as it's likely been patched in their target environments.");
