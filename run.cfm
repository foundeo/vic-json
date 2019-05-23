<cfsetting requesttimeout="9000">
<cfscript>
	
	files = directoryList(expandPath("./cve-db/database/java/"), true, "path", "*.yaml");
	i = 0;
	data = {};
	for (f in files) {
		processYAMLFile(f);
		writeOutput(f & "<br>");
		cfflush();
	}

	fileWrite(expandPath("./database/vic-latest.json"), serializeJSON(data), "utf-8");

	if(url.keyExists("debug")) {
		writeDump(data);	
	}

	writeOutput("DONE");

	function processYAMLFile(filePath) {
		local.snakeYaml = createObject("java", "org.yaml.snakeyaml.Yaml");
		local.yaml = local.snakeYaml.load(fileRead(arguments.filePath));
		local.summary = "";
		local.package = "";
		local.v = "";
		if (yaml.keyExists("title")) {
			summary = yaml["title"];
		}
		if (yaml.keyExists("description")) {
			summary = summary & ". " & yaml["description"];
		}
		for (package in yaml["affected"]) {
			local.packageID = package["groupId"] & ":" & package["artifactId"];
			data[packageID] = {"vulnerabilities":[], "extractors":{}};
			data[packageID].extractors["filename"]  = [ "#package["artifactId"]#-(§§version§§).jar"];
			if (!package.keyExists("fixedin")) {
				if (url.keyExists("debug")) {
					writeOutput("<h3>Missing fixedin in: #f#</h3>");
				}
				continue;
			}
			for (v in package["fixedin"]) {
				v = listFirst(v);
				if (!reFind("[a-zA-Z]", v)) {
					v = replace(v, ">=", "");

					vuln = { "below":v, "identifiers": {"CVE":["CVE-#yaml["cve"]#"], "summary":summary }, "info":[]};
					
					if (yaml.keyExists("references")) {
						for (ref in yaml["references"]) {
							vuln.info.append(ref);
						}
					}
					data[packageID].vulnerabilities.append(vuln);
				}
			}

			if (arrayLen(data[packageID].vulnerabilities) == 0) {
				continue;
			}

			
			if (yaml.keyExists("package_urls")) {
				data[packageID].extractors["hashes"] = {};
				arrayEach(yaml["package_urls"], function(p) {
					local.fileName = listLast(p, "/");
					if (arrayLen(yaml["affected"]) == 1 || findNoCase(package["artifactId"], fileName) ) {
						data[packageID].extractors["hashes"][urlToSha1(p)] = reReplace(fileName, "#package["artifactId"]#-(.+)\.jar", "\1");
					}
				}, true, 20);
				
			}
			
		}
		i++;
		
		if (url.keyExists("debug")) {
			writeDump(yaml);
			if (i>3) {
				break;	
			}
		}
	}
	

	function urlToSha1(address) {
		var tempPath = getTempDirectory() & createUUID() & ".jar";
		cfhttp(url="#arguments.address#", method="get", file="#tempPath#", getasbinary="true");
		if (!fileExists(tempPath)) {
			return repeatString("0", 40);
		}
		return fileSha1(tempPath);
	}

	function fileSha1(path) {
		var fIn = createObject("java", "java.io.FileInputStream").init(path);
		return createObject("java", "org.apache.commons.codec.digest.DigestUtils").sha1Hex(fIn);
	}
</cfscript>
