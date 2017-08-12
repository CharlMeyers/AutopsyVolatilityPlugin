from subprocess import Popen, PIPE


class VolatilityServiceClass:
    def __init__(self, volatiltiyExecutable, profile, dbName):
        self.volatility = volatiltiyExecutable
        self.profile = profile
        self.database = dbName

    def hivescan(self, file):
        pipe = Popen([self.volatility, "-f ", file, " --profile=", self.profile,
                      "hivelist --output=sqlite --output-file=", self.database])

        return pipe.communicate()[0]

    def getPasswords(self, file, system, sam):
        pipe = Popen([self.volatility, "-f", file, "--profile=", self.profile, "hashdump -y", system, "-s", sam,
                      "--output=sqlite --output-file=", self.database])

        return pipe.communicate()[0]