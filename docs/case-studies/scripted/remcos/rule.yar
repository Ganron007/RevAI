// yara_gen_v2.py — 2026-08-03T21:35:12.098928+00:00
rule CADRE_v2_unknown_1b0eb55bb50d {
    meta:
        description = "CADRE-RevAI v2 auto rule for unknown"
        sha256 = "1b0eb55bb50d0286b192accbe408826c4c2e6c59a78d52743ce4f84ac0b1d6d0"
        family = "unknown"
        cadre_revai = true
        severity = "high"
        confidence = "medium"
    strings:
        $s0 = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"" ascii wide
        $s1 = "SELECT 'CREATE UNIQUE INDEX vacuum_db.' || substr(sql,21)   FROM sqlite_master WHERE sql LIKE 'CREATE UNIQUE INDEX %'" ascii wide
        $s2 = "SELECT 'DELETE FROM vacuum_db.' || quote(name) || ';' FROM vacuum_db.sqlite_master WHERE name='sqlite_sequence'" ascii wide
        $s3 = "UPDATE \"%w\".%s SET sql = substr(sql,1,%d) || ', ' || %Q || substr(sql,%d) WHERE type = 'table' AND name = %Q" ascii wide
        $s4 = "SELECT 'CREATE INDEX vacuum_db.' || substr(sql,14)  FROM sqlite_master WHERE sql LIKE 'CREATE INDEX %'" ascii wide
        $s5 = "qualified table names are not allowed on INSERT, UPDATE, and DELETE statements within triggers" ascii wide
        $s6 = "number of columns in foreign key does not match the number of columns in the referenced table" ascii wide
        $s7 = "UPDATE sqlite_temp_master SET sql = sqlite_rename_trigger(sql, %Q), tbl_name = %Q WHERE %s;" ascii wide
        $s8 = "UPDATE %Q.%s SET type='table', name=%Q, tbl_name=%Q, rootpage=0, sql=%Q WHERE rowid=#%d" ascii wide
        $s9 = "UPDATE %Q.%s SET type='%s', name=%Q, tbl_name=%Q, rootpage=#%d, sql=%Q WHERE rowid=#%d" ascii wide
        $s10 = "the NOT INDEXED clause is not allowed on UPDATE or DELETE statements within triggers" ascii wide
        $s11 = "the INDEXED BY clause is not allowed on UPDATE or DELETE statements within triggers" ascii wide
        $h0 = { 4D 5A 90 00 03 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}