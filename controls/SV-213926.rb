control 'SV-213926' do
  title 'SQL Server must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'DBMSs handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. These cryptographic mechanisms may be native to SQL Server or implemented via additional software or operating system/file system settings, as appropriate to the situation.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. Organizations have the flexibility to either encrypt all information on storage devices (i.e., full disk encryption) or encrypt specific data structures (e.g., files, records, or fields). 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', "Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information. 

If no information is identified as requiring such protection, this is not a finding. 

Review the configuration of SQL Server, Windows, and additional software as relevant. 

If full-disk encryption is required, and Windows or the storage system is not configured for this, this is a finding. 

If database transparent data encryption (TDE) is called for, check whether it is enabled: 

SELECT
DB_NAME(database_id) AS [Database Name], CASE encryption_state WHEN 0 THEN 'No database encryption key present, no encryption' 
WHEN 1 THEN 'Unencrypted' 
WHEN 2 THEN 'Encryption in progress' 
WHEN 3 THEN 'Encrypted' 
WHEN 4 THEN 'Key change in progress' 
WHEN 5 THEN 'Decryption in progress' 
WHEN 6 THEN 'Protection change in progress' 
END AS [Encryption State]
FROM sys.dm_database_encryption_keys

For each user database for which encryption is called for and it is marked Unencrypted, this is a finding. 

If table/column encryption and/or a separation between those who own the data (and can view it) and those who manage the data (but should have no access) is required for PII or similar types of data, use Always Encrypted.  The details for configuring Always Encrypted are located here: https://msdn.microsoft.com/en-us/library/mt163865.aspx.

Review the definitions and contents of the relevant tables/columns for the Always Encryption settings, if any of the information defined as requiring cryptographic protection is not encrypted this is a finding."
  desc 'fix', 'Where full-disk encryption is required, configure Windows and/or the storage system to provide this. 

Where transparent data encryption (TDE) is required, create a master key, obtain a certificate protected by the master key, create a database encryption key and protect it by the certificate, and then set the database to use encryption. For guidance from MSDN on how to do this: https://msdn.microsoft.com/en-us/library/bb934049.aspx. 

Where table/column encryption is required, enable encryption on the tables/columns in question. For guidance from the Microsoft Developer Network on how to do this with Always Encrypted: https://msdn.microsoft.com/en-us/library/mt163865.aspx.'
  impact 0.5
  tag check_id: 'C-15144r313210_chk'
  tag severity: 'medium'
  tag gid: 'V-213926'
  tag rid: 'SV-213926r879799_rule'
  tag stig_id: 'SQL6-D0-003300'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-15142r313211_fix'
  tag legacy: ['SV-93821', 'V-79115']
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
