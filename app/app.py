import subprocess, os, json, re 

#Get the working directory of the repo from the step
directory = os.getenv("WORKING_DIRECTORY")

"""
Run the snyk test command, the output will be in json and we will query the remediation object and get the vulnerable package, the package to upgrade to, and the dependencies. 

Will return an object like below and write contents to package_change.json

[
  "<OLD_PACKAGE>",
  "<NEW_PACKAGE>",
  [
    "<DEPENDENCIES>",
    ...
  ]
]
"""
command = f"snyk test {directory} --json | jq '[.remediation.upgrade[] | [.upgradeTo, .[\"upgradeTo\"], .upgrades]]' > package_change.json"

subprocess.run(command, shell=True)

#Open the json file we created and load it as a data structure 
with open('package_change.json') as f:
    package_list = json.load(f)

#Store all of the new suggested versions from the snyk output in an array 
new_versions = []

"""
For every vulnerable package, if the new package and old package are the same, we need to update the dependencies in the gemfile 

If the new package is different than the old package, we simply need to make an update to the gemfile 
"""
for package in package_list: 
    #For each new package mentioned in our command output, append to the package list 
    new_versions.append(package[1])


#Need a function to change old_version to new version 
def update_version(news):
    #Open Gemfile, and read lines into a variable 
    with open(f"{directory}/Gemfile", 'r+') as f:
        lines = f.readlines()
        #For each new package mentioned, split out the name and package version as variables 
        for new_version in news: 
            gem_name, version =  new_version.split('@')
            new_line = f"gem '{gem_name}', '{version}'"
            #Search through the Gemfile and replace each old occurance of the package with the new version
            for i,line in enumerate(lines):
                if re.search(f"[\'\"]{gem_name}[\'\"]", line):
                    print (f"We will replace {lines[i]} with {new_line}")
                    lines[i] = new_line
                    break 
        #Write changes back to gemfile
        f.seek(0)
        f.writelines(lines)
        f.truncate


update_version(new_versions)






