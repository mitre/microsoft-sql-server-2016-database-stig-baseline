# [WIP] Microsoft SQL Server 2016 Database STIG InSpec Profile

## microsoft-sql-server-2016-database-stig-baseline  

InSpec profile to validate the secure configuration of Microsoft SQL Server 2016 *Database, against [DISA](https://iase.disa.mil/stigs/)'s Microsoft SQL Server 2016 Database Security Technical Implementation Guide (STIG) Version 2, Release 8.

\*In the Microsoft SQL Server domain, a `database` (often abbreviated as DB) is a logical collection of data stored in files and managed not by the operating system alone but by the Database Management System (DBMS). Multiple databases may exist under one DBMS instance. There are always at least four system databases supporting an instance, and there will normally be one database (possibly more) supporting an application.

## Getting Started  
It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely over __winrm__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

**-----UPDATE ME -------**
```yaml
# username MSSQL DB Server
user: ''

# password MSSQL DB Server
password: ''

# hostname MSSQL DB Server
host: ''

# instance name MSSQL DB Server
instance: ''

# port MSSQL DB Server
port: 49789

# name of the specific DB being evaluated within the MSSQL server
db_name: ''

# Changes in categorized information must be tracked
server_trace_or_audit_required: true

# Set to true If SQL Server Trace is in use for audit purposes
server_trace_implemented: true

# Set to true If SQL Server Audit is in use for audit purposes
server_audit_implemented: true

# Specify if  SQL Server Audit is not in use at the database level
server_audit_at_database_level_required: true

# User with `ALTER ANY DATABASE AUDIT` or `CONTROL` permission
approved_audit_maintainers: []

# name of the timed job that automatically checks all system and user-defined procedures for being modified
track_stored_procedures_changes_job_name: ''

# name of the timed job that automatically checks all system and user-defined triggers for being modified
track_triggers_changes_job_name: ''

# name of the timed job that automatically checks all system and user-defined functions for being modified
track_functions_changes_job_name: ''

# identify SQL Server accounts authorized to own database objects
authorized_principals: []

# Set to true if data at rest encryption is required
data_at_rest_encryption_required: true

# Set to true if full disk encryption is in place
full_disk_encryption_inplace: false

# Set to true if security labeling is required
security_labeling_required: true
```

# Running This Baseline Directly from Github

```
# How to run
inspec exec https://github.com/mitre/microsoft-sql-server-2016-database-stig-baseline/archive/master.tar.gz -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/microsoft-sql-server-2016-database-stig-baseline
inspec archive microsoft-sql-server-2016-database-stig-baseline
inspec exec <name of generated archive> -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd microsoft-sql-server-2016-database-stig-baseline
git pull
cd ..
inspec archive microsoft-sql-server-2016-database-stig-baseline --overwrite
inspec exec <name of generated archive> -t winrm://<hostip> --user '<admin-account>' --password=<password> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Emily Rodriguez
* George Dias

## Special Thanks 

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/microsoft-sql-server-2016-database-stig-baseline/issues/new).
