# ACRES Database

## Overview

The A.I.-enhanced Cyber Resiliency Evaluation System (ACRES) Database is designed to support cyber resiliency assessments by storing and managing data related to Advanced Persistent Threats (APTs), vulnerabilities, infrastructure, and scoring systems. This database schema is part of a project for IT 310 A - Database Technology that was a spinoff from a Navy Cyber Resiliency Measurement Challenge. Currently, the repository consits of several DDL files to generate a MySQL database and populate the data (one to create schema and tables only, one to populate the data, and a combined DDL file for both), a white paper report, and a presentation deck.

## Authors

- Kristian Alleyne, B.S. Information Technology w/ Cybersecurity minor
- Richard Flores, B.S. Information Technology w/ Cybersecurity and Digital Forensics minors
- Claire Kamobaya, B.S. Cybersecurity
- Matthew Penn B.S. Cybersecurity
- Professor: Dr. Xiang Liu

## Schema Structure

The database schema is organized into several tables to capture various aspects of cyber threats and infrastructure. Below is an overview of the tables and their purposes:

### Tables

> #### APT_GROUPS:
> Stores information about different APT groups, including aliases and descriptions. Primary Key: apt_group.
> 
> #### CRITICALITY_DEFINITIONS:
> Defines criticality levels for infrastructure components based on downtime allowed. Primary Key: criticality_value.
> 
> #### VULNERABILITIES_DATA:
> Contains data on vulnerabilities, including CVE numbers, scores, and impact details. Includes many constraints for data validation. Primary Key: cve_number.
> 
> #### INFRASTRUCTURE_CATEGORIES:
> Lists categories for infrastructure components. Primary Key: category_id (auto-number).
> 
> #### HARDWARE:
> Details unique within the infrastructure, including make, model, and description. Primary Key: hardware_id (auto-number).
> 
> #### ENDPOINT_NODES:
> Captures unqique endpoint devices within the network. Primary Key: endpoint_id (auto-number).
> 
> #### HARDWARE_MAPPING:
> Maps and details individual hardware instances within system infrastructure. Composite Key: hardware_id, serial_number.
>
> #### SOFTWARE_FIRMWARE:
> Stores software and firmware details installed on endpoints. Primary Key: software_id (auto-number).
> 
> ### SYSTEM_SCORING:
> AI evaluation scoring of system based on system summaries and security best practices in physical security, personel training, and operating policies. Composite Key: apt_group and score_name
> 
> #### FUNCTION_DEFINITIONS:
> Defines functions within the system with associated criticality values. Primary Key: function_number.
> 
> #### FUNCTION_MAPPING:
> Maps functions to endpoint nodes. Composite Key: endpoint_id and function_number.
> 
> #### SOFTWARE_FIRMWARE_MAPPING:
> Links software/firmware to endpoints. Composite Key: endpoint_id and software_id.
> 
> #### VULNERABILITY_INSTANCES:
> Associates vulnerabilities with specific software instances. Composite Key: cve_number and software_id.
> 
> #### APT_CVE_SCORING
> Scores APT groups based on their association with specific vulnerabilities. Composite Key: cve_number and apt_group.

## Usage

### To set up the database:

1. Execute the DDL script provided in this repository to create the schema and tables.
2. Insert initial data as needed using the provided SQL insert statements.
   #### OR
- Run the combined ACRES Database DDL with sample data to create and populate data in one step.

### Data Insertion

Sample data insertion has been provided for all tables, illustrating how to populate the database with initial threat group data, infrastructure details for the system under evaluation, and sample output from ACRES software tool analysis.

### Notes

Ensure that all foreign key constraints are respected when populating tables.
The schema includes various constraints to maintain data integrity; review these before inserting new data.
