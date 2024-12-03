/*
Query 1
*/
SELECT 
    base_severity, 
    AVG(nvd_score) AS average_nvd_score
FROM 
    VULNERABILITIES_DATA
WHERE 
    base_severity = 'HIGH'
GROUP BY 
    base_severity;

/*
Query 2
*/
SELECT 
    vd.cve_number, 
    vd.description, 
    vd.nvd_score
FROM 
    VULNERABILITIES_DATA vd
JOIN 
    CRITICALITY_DEFINITIONS cd 
    ON vd.base_severity = cd.criticality_name
WHERE 
    vd.nvd_score > 8.0 
    AND cd.criticality_name = 'HIGH';


/*
Query 3
*/
select ag.apt_group, vd.cve_number, acs.score as "exploitation likelihood", vd.description as vulnerability_desc
from 
    apt_groups ag
inner join 
    apt_cve_scoring acs on ag.apt_group = acs.apt_group
inner join 
    vulnerabilities_data vd on acs.cve_number = vd.cve_number
where acs.score >= .6;


/*
Query 4
*/ 
SELECT 
    sf.software_id,
    vd.nvd_score, vd.cve_number
FROM 
    SOFTWARE_FIRMWARE sf
LEFT OUTER JOIN 
    VULNERABILITY_INSTANCES vi 
    ON sf.software_id = vi.software_id
LEFT OUTER JOIN 
    VULNERABILITIES_DATA vd 
    ON vi.cve_number = vd.cve_number
WHERE 
    vd.base_severity = 'CRITICAL' OR vd.base_severity = 'HIGH' OR vd.base_severity IS NULL
ORDER BY 
    sf.software_id;