# ACRES Database

## Overview
The A.I.-enhanced Cyber Resiliency Evaluation System (ACRES) Database is designed to support cyber resiliency assessments by storing and managing data related to Advanced Persistent Threats (APTs), vulnerabilities, infrastructure, and scoring systems. This database schema is part of a project for IT 310 A - Database Technology that was a spinoff from a Navy Cyber Resiliency Measurement Challenge. Currently, the repository consits of several DDL files to generate a MySQL database and populate the data (one to create schema and tables only, one to populate the data, and a combined DDL file for both), a white paper report, and a presentation deck.

## Authors
Kristian Alleyne, B.S. Information Technology w/ Cybersecurity minor
Richard Flores, B.S. Information Technology w/ Cybersecurity, Digital Forensics, and Network Security minors
Claire Kamobaya, B.S. Cybersecurity
Matthew Penn B.S. Cybersecurity
Professor: Dr. Xiang Liu

## Schema Structure
The database schema is organized into several tables to capture various aspects of cyber threats and infrastructure. Below is an overview of the tables and their purposes:
Tables

### APT_GROUPS:
  Primary Key: apt_group
  Stores information about different APT groups, including aliases and descriptions.

### CRITICALITY_DEFINITIONS:
  Primary Key: criticality_value
  Defines criticality levels for infrastructure components based on downtime allowed.

### VULNERABILITIES_DATA:
  Primary Key: cve_number
  Contains data on vulnerabilities, including CVE numbers, scores, and impact details. Includes many constraints for data validation.

### INFRASTRUCTURE_CATEGORIES:
  Primary Key: category_id (auto-number)
  Lists categories for infrastructure components.

### INFRASTRUCTURE_NODES:
  Primary Key: infra_id (auto-number)
  Details nodes within the infrastructure, including make, model, and category.

### ENDPOINT_NODES:
  Primary Key: endpoint_id (auto-number)
  Captures unqique endpoint devices within the network.

### SOFTWARE_FIRMWARE:
  Primary Key: software_id (auto-number)
  Stores software and firmware details installed on endpoints.
  
### SYSTEM_SCORING:
  Composite Primary Key: apt_group and score_name
  AI evaluation scoring of system based on system summaries and security best practices in physical security, personel training, and operating policies.

### FUNCTION_DEFINITIONS:
  Primary Key: function_number
  Defines functions within the system with associated criticality values.

### FUNCTION_MAPPING:
  Composite Primary Key: endpoint_id and function_number
  Maps functions to endpoint nodes.
        
### SOFTWARE_FIRMWARE_MAPPING:
  Composite Primary Key: endpoint_id and software_id
  Links software/firmware to endpoints.

### VULNERABILITY_INSTANCES:
  Composite Primary Key: cve_number and software_id
  Associates vulnerabilities with specific software instances.

### APT_CVE_SCORING
  Composite Primary Key: cve_number and apt_group
  Scores APT groups based on their association with specific vulnerabilities.

## Usage
### To set up the database:
1. Execute the DDL script provided in this repository to create the schema and tables.
2. Insert initial data as needed using the provided SQL insert statements.
   OR
Run the combined ACRES Database DDL with sample data to create and populate data in one step.

## Data Insertion
Sample data insertion has been provided for all tables, illustrating how to populate the database with initial threat group data, infrastructure details for the system under evaluation, and sample output from ACRES software tool analysis.

### Notes
Ensure that all foreign key constraints are respected when populating tables.
The schema includes various constraints to maintain data integrity; review these before inserting new data.
