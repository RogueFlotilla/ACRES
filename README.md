# ACRES Database
Currently, a DDL file to generate a MySQL database that was a final project for IT 310, Database Technology, that was a spinoff of a Navy Cyber Resiliency Measurement Challenge. The file also populates the database with sample data.

## Overview
The A.I.-enhanced Cyber Resiliency Evaluation System (ACRES) Database is designed to support cyber resiliency assessments by storing and managing data related to Advanced Persistent Threats (APTs), vulnerabilities, infrastructure, and scoring systems. This database schema is part of a project for IT 310 A - Database Technology.
###Authors

    Kristian Alleyne
    Richard Flores
    Claire Kamobaya
    Matthew Penn
    Supervisor: Dr. Xiang Liu

Date
December 10, 2024
Schema Structure
The database schema is organized into several tables to capture various aspects of cyber threats and infrastructure. Below is an overview of the tables and their purposes:
Tables

    APT_GROUPS
        Stores information about different APT groups, including aliases and descriptions.
        Primary Key: apt_group
    CRITICALITY_DEFINITIONS
        Defines criticality levels for infrastructure components based on downtime allowed.
        Primary Key: criticality_value
    VULNERABILITIES_DATA
        Contains data on vulnerabilities, including CVE numbers, scores, and impact details.
        Primary Key: cve_number
        Includes various constraints for data validation.
    INFRASTRUCTURE_CATEGORIES
        Lists categories for infrastructure components.
        Primary Key: category_id
    INFRASTRUCTURE_NODES
        Details nodes within the infrastructure, including make, model, and category.
        Primary Key: infra_id
    ENDPOINT_NODES
        Captures endpoint devices within the network.
        Primary Key: endpoint_id
    SOFTWARE_FIRMWARE
        Stores software and firmware details installed on endpoints.
        Primary Key: software_id
        Unique constraint on software make, name, and version.
    SYSTEM_SCORING
        Evaluates APT groups based on various scoring criteria.
        Primary Key: Composite of apt_group and score_name
        Foreign Key references to APT_GROUPS
    FUNCTION_DEFINITIONS
        Defines functions within the system with associated criticality values.
        Primary Key: function_number
        Foreign Key references to CRITICALITY_DEFINITIONS
    FUNCTION_MAPPING
        Maps functions to endpoint nodes.
        Primary Key: Composite of endpoint_id and function_number
        Foreign Key references to ENDPOINT_NODES and FUNCTION_DEFINITIONS
    SOFTWARE_FIRMWARE_MAPPING
        Links software/firmware to endpoints.
        Primary Key: Composite of endpoint_id and software_id
        Foreign Key references to ENDPOINT_NODES and SOFTWARE_FIRMWARE
    VULNERABILITY_INSTANCES
        Associates vulnerabilities with specific software instances.
        Primary Key: Composite of cve_number and software_id
        Foreign Key references to VULNERABILITIES_DATA and SOFTWARE_FIRMWARE
    APT_CVE_SCORING
        Scores APT groups based on their association with specific vulnerabilities.
        Primary Key: Composite of cve_number and apt_group
        Foreign Key references to VULNERABILITIES_DATA and APT_GROUPS

Data Insertion
Sample data insertion has been provided for the APT_GROUPS table, illustrating how to populate the database with initial threat group data.
Usage
To set up the database:

    Execute the DDL script provided in this repository to create the schema and tables.
    Insert initial data as needed using the provided SQL insert statements.

Notes

    Ensure that all foreign key constraints are respected when populating tables.
    The schema includes various constraints to maintain data integrity; review these before inserting new data.

This README provides a high-level overview of the ACRES database schema, its structure, and usage instructions for setting up the database environment.
