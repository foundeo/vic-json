#!/bin/bash
mkdir cve-db
git clone https://github.com/victims/victims-cve-db.git cve-db

mvn dependency:copy-dependencies