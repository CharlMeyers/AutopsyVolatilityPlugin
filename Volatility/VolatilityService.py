from subprocess import Popen, PIPE


class VolatilityServiceClass:
    database = ""

    def __init__(self, volatiltiyExecutable, profile):
        self.volatility = volatiltiyExecutable
        self.profile = profile

    def setDbName(self, dbName):
        self.database = dbName

    def hivelist(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile,
                      "hivelist", "--output=sqlite", "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def getPasswords(self, file, system, sam, fileName):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "hashdump", "-y", system, "-s", sam,
                      "--output=text", "--output-file=" + fileName], stdout=PIPE, stderr=PIPE)
        return pipe

    def hivedump(self, file, address, output):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "hivedump", "-o", address,
                      "--output=json", "--output-file=" + output], stdout=PIPE, stderr=PIPE)
        return pipe

    def pslist(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "pslist", "--output=sqlite",
                      "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def psscan(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "psscan", "-V", "--output=sqlite",
                      "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def filescan(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "filescan", "-V", "--output=sqlite",
                      "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def netscan(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "netscan", "-V", "--output=sqlite",
                      "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def dlldump(self, file, outputDir):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "dlldump", "-D", outputDir],
                     stdout=PIPE, stderr=PIPE)
        return pipe

    def dumpregistry(self, file, outputDir):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "dumpregistry", "-D", outputDir],
                     stdout=PIPE, stderr=PIPE)
        return pipe

    def procdump(self, file, processId, outputDir):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "procdump", "-D", outputDir,
                      "-p", processId], stdout=PIPE, stderr=PIPE)
        return pipe

