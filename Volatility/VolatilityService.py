from subprocess import Popen, PIPE


class VolatilityServiceClass:
    database = ""

    def __init__(self, volatiltiyExecutable, profile):
        self.volatility = volatiltiyExecutable
        self.profile = profile

    def setDbName(self, dbName):
        self.database = dbName

    def hivescan(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile,
                      "hivelist", "--output=sqlite", "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def getPasswords(self, file, system, sam, fileName):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "hashdump", "-y", system, "-s", sam,
                      "--output=text", "--output-file=" + fileName], stdout=PIPE, stderr=PIPE)
        return pipe

    def hiveDump(self, file, address):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "hivedump", "-o", address,
                      "--output=sqlite", "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def printkey(self, file, key):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "printkey", "-K", key,
                      "--output=sqlite", "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe

    def psScan(self, file):
        pipe = Popen([self.volatility, "-f", file, "--profile=" + self.profile, "psscan", "--output=sqlite",
                      "--output-file=" + self.database], stdout=PIPE, stderr=PIPE)
        return pipe


