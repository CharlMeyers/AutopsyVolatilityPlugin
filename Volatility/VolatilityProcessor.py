import inspect
import os
import hashlib
import json
from shutil import copyfile
from VolatilityService import VolatilityServiceClass

from java.awt import GridBagLayout
from java.awt import GridBagConstraints
from javax.swing import JPanel
from javax.swing import JLabel
from javax.swing import JTextField
from javax.swing import JButton
from javax.swing import JFileChooser
from javax.swing import JComboBox
from javax.swing.filechooser import FileNameExtensionFilter

from java.util.logging import Level
from java.sql import DriverManager, SQLException
from java.lang import Class

from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import ModuleDataEvent

class VolatilityIngestModuleFactory(IngestModuleFactoryAdapter):
    def __init__(self):
        self.settings = None

    moduleName = "Volatility Processor"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Run Volatility against a Memory Image"

    def getModuleVersionNumber(self):
        return "1.0"

    def getDefaultIngestJobSettings(self):
        return VolatilityIngestModuleSettings()

    def hasIngestJobSettingsPanel(self):
        return True

    def getIngestJobSettingsPanel(self, settings):
        if not isinstance(settings, VolatilityIngestModuleSettings):
            raise IllegalArgumentException("Settings expected to be instnce of SampleIngestModuleSettings")
        self.settings = settings

        return VolatilityIngestModuleUISettingsPanel(self.settings)

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return VolatilityIngestModule(self.settings)


class VolatilityIngestModuleUISettingsPanel(IngestModuleIngestJobSettingsPanel):
    def __init__(self, settings):
        head, tail = os.path.split(os.path.abspath(__file__))
        self.absolutePath = head
        self.database = head + "\\VolatilitySettings.db"
        self.localSettings = settings
        self.initLayout()

    def checkDatabase(self):
        runInsertStatements = False
        if not os.path.isfile(self.database):
            runInsertStatements = True

        connection = None
        statement= None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)
            if runInsertStatements:
                with open(self.absolutePath + "\\InsertStatements.sql", "r") as file:
                    count = 0
                    for query in file:
                        # Exclude any lines that are empty or contain comment
                        if query != "" and "--" not in query:
                            count += 1
                            try:
                                preparedStatement = connection.prepareStatement(query)
                                preparedStatement.executeUpdate()
                            except SQLException as ex:
                                self.messageLabel.setText("Error at: " + query + "<br />" + ex.message)
                    self.messageLabel.setText("Database created successfully")

            try:
                statement = connection.createStatement()
                query = 'SELECT name, value FROM settings'
                results = statement.executeQuery(query)
                while results.next():
                    if results.getString("name") == "VolatilityExecutableDirectory":
                        self.volatilityDirTextField.setText(results.getString("value"))
                        self.localSettings.setVolatilityDir(results.getString("value"))
                    if results.getString("name") == "VolatilityVersion":
                        self.versionComboBox.setSelectedItem(results.getString("value"))
                    if results.getString("name") == "VolatilityProfile":
                        self.profileComboBox.setSelectedItem(results.getString("value"))
                self.messageLabel.setText("Saved settings loaded successfully")
            except SQLException as ex:
                self.messageLabel.setText("Error reading settings database: " + ex.message)
            finally:
                if statement:
                    statement.close()
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB: " + ex.message)
        finally:
            if connection:
                connection.close()

    def findDir(self, event):
        fileChooser = JFileChooser()
        fileExtentionFilter = FileNameExtensionFilter("Executable Files (*.exe)", ["exe"])
        fileChooser.addChoosableFileFilter(fileExtentionFilter)

        result = fileChooser.showDialog(self.mainPanel, "Select File")

        if result == JFileChooser.APPROVE_OPTION:
            file = fileChooser.getSelectedFile()
            canonicalPath = file.getCanonicalPath()

            self.localSettings.setVolatilityDir(canonicalPath)
            self.volatilityDirTextField.setText(canonicalPath)

    def saveSettings(self, event):
        connection = None
        statement = None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)

            try:
                statement = connection.createStatement()
                query = 'SELECT count(*) as RowCount FROM settings'
                results = statement.executeQuery(query)
                settingsCount = int(results.getString("RowCount"))

                if settingsCount > 3:
                    directoryStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityExecutableDirectory';"
                    )
                    versionStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityVersion';"
                    )
                    profileStatement = connection.prepareStatement(
                        "UPDATE settings SET value = ? WHERE name = 'VolatilityProfile';"
                    )
                else:
                    directoryStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityExecutableDirectory', ?);")
                    versionStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityVersion', ?);")
                    profileStatement = connection.prepareStatement(
                        "INSERT INTO settings (name, value) VALUES ('VolatilityProfile', ?);"
                    )

                directoryStatement.setString(1, self.volatilityDirTextField.getText())
                versionStatement.setString(1, self.versionComboBox.getSelectedItem())
                profileStatement.setString(1, self.profileComboBox.getSelectedItem())

                directoryStatement.executeUpdate()
                versionStatement.executeUpdate()
                profileStatement.executeUpdate()
                self.messageLabel.setText("Settings saved successfully")
                self.localSettings.setVolatilityDir(self.volatilityDirTextField.getText())
            except SQLException as ex:
                self.messageLabel.setText("Error reading settings database: " + ex.message)
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB: " + ex.message)
        finally:
            if statement:
                statement.close()

            if connection:
                connection.close()

    def getProfiles(self):
        connection = None
        statement = None

        try:
            Class.forName("org.sqlite.JDBC").newInstance()
            connection = DriverManager.getConnection("jdbc:sqlite:" + self.database)

            version = self.versionComboBox.getSelectedItem()
            statement = connection.createStatement()
            query = "SELECT name FROM profiles WHERE version = '" + version + "';"
            results = statement.executeQuery(query)
            profiles = []
            while results.next():
                profiles.append(results.getString("name"))

            # statement.close()
            # connection.close()
            return profiles
        except SQLException as ex:
            self.messageLabel.setText("Error opening settings DB:\n" + ex.message)
        finally:
            if statement:
                statement.close()
            if connection:
                connection.close()

    def changeVersion(self, event):
        self.localSettings.setVersion(event.item)
        profileList = self.getProfiles()
        self.profileComboBox.removeAllItems()
        for profile in profileList:
            self.profileComboBox.addItem(profile)

    def changeProfile(self, event):
        self.localSettings.setProfile(event.item)

    def getSettings(self):
        return self.localSettings

    def initLayout(self):
        self.mainPanel = JPanel()

        self.gridBagPanel = GridBagLayout()
        self.gridBagConstraints = GridBagConstraints()
        self.mainPanel.setLayout(self.gridBagPanel)

        # Volatility Executable Path
        self.dirLabel = JLabel("Volatility Executable Directory")
        self.dirLabel.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 1
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 1
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.dirLabel, self.gridBagConstraints)
        self.mainPanel.add(self.dirLabel)

        self.volatilityDirTextField = JTextField(10)
        self.volatilityDirTextField.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 3
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.volatilityDirTextField, self.gridBagConstraints)
        self.mainPanel.add(self.volatilityDirTextField)

        self.findVolatilityPathButton = JButton("Find Dir", actionPerformed=self.findDir)
        self.findVolatilityPathButton.setEnabled(True)
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 3
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.findVolatilityPathButton, self.gridBagConstraints)
        self.mainPanel.add(self.findVolatilityPathButton)

        self.Blank3 = JLabel(" ")
        self.Blank3.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 9
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank3, self.gridBagConstraints)
        self.mainPanel.add(self.Blank3)

        # Version selector
        self.versionLabel = JLabel("Version:")
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 11
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.versionLabel, self.gridBagConstraints)
        self.mainPanel.add(self.versionLabel)

        self.versionList = ("2.5", "2.6")
        self.versionComboBox = JComboBox(self.versionList)
        self.versionComboBox.itemStateChanged = self.changeVersion
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 11
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.versionComboBox, self.gridBagConstraints)
        self.mainPanel.add(self.versionComboBox)

        self.Blank4 = JLabel(" ")
        self.Blank4.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 13
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank4, self.gridBagConstraints)
        self.mainPanel.add(self.Blank4)

        # Profile selector
        self.profileLabel = JLabel("Profile:")
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 19
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.profileLabel, self.gridBagConstraints)
        self.mainPanel.add(self.profileLabel)

        self.profileList = self.getProfiles()
        self.profileComboBox = JComboBox(self.profileList)
        self.profileComboBox.itemStateChanged = self.changeProfile
        self.gridBagConstraints.gridx = 7
        self.gridBagConstraints.gridy = 19
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 1
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.profileComboBox, self.gridBagConstraints)
        self.mainPanel.add(self.profileComboBox)

        self.Blank5 = JLabel(" ")
        self.Blank5.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 13
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank5, self.gridBagConstraints)
        self.mainPanel.add(self.Blank5)

        self.Blank2 = JLabel(" ")
        self.Blank2.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 22
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank2, self.gridBagConstraints)
        self.mainPanel.add(self.Blank2)

        # Save button
        self.saveButton = JButton("Save Settings", actionPerformed=self.saveSettings)
        self.saveButton.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 24
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.saveButton, self.gridBagConstraints)
        self.mainPanel.add(self.saveButton)

        self.Blank6 = JLabel(" ")
        self.Blank6.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 26
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Blank6, self.gridBagConstraints)
        self.mainPanel.add(self.Blank6)

        # Message
        self.Label3 = JLabel("Message:")
        self.Label3.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 27
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 1
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.Label3, self.gridBagConstraints)
        self.mainPanel.add(self.Label3)

        self.messageLabel = JLabel("")
        self.messageLabel.setEnabled(True)
        self.gridBagConstraints.gridx = 2
        self.gridBagConstraints.gridy = 31
        self.gridBagConstraints.gridwidth = 1
        self.gridBagConstraints.gridheight = 1
        self.gridBagConstraints.fill = GridBagConstraints.BOTH
        self.gridBagConstraints.weightx = 2
        self.gridBagConstraints.weighty = 0
        self.gridBagConstraints.anchor = GridBagConstraints.NORTH
        self.gridBagPanel.setConstraints(self.messageLabel, self.gridBagConstraints)
        self.mainPanel.add(self.messageLabel)

        self.checkDatabase()

        self.add(self.mainPanel)


class VolatilityIngestModule(DataSourceIngestModule):
    def __init__(self, settings):
        self.context = None
        self.localSettings = settings
        self.databaseFile = ""
        self.isAutodetect = False
        self.logger = Logger.getLogger(VolatilityIngestModuleFactory.moduleName)

    def log(self, level, message):
        self.logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], message)

    def startUp(self, context):
        self.context = context
        self.VolatilityDir = self.localSettings.getVolatilityDir()
        self.Profile = self.localSettings.getProfile()

        if self.Profile == 'Autodetect':
            self.isAutodetect = True
        else:
            self.isAutodetect = False

        message = "<ul>" + \
            "<li>Volatility executable at: " + self.VolatilityDir + "</li>" + \
            "<li>Selected profile: " + self.Profile + "</li>" + "</ul>"

        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                              "Volatiity Settings Loaded", message)
        IngestServices.getInstance().postMessage(inbox)

        if not os.path.exists(self.VolatilityDir):
            raise IngestModuleException("Volatility executable does not exist")

        self.log(Level.INFO, "Volatility Processor Loaded")

    def progressCount(self, processNum, fileNum):
        return processNum + (self.processCount * (fileNum - 1))

    def process(self, dataSource, progressBar):
        logHeader = "Volatility Processor -- "
        progressBar.switchToIndeterminate()
        BLOCKSIZE = 200 * 1024 * 1024 # about 200 megabyte
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Volatility Process Started")
        IngestServices.getInstance().postMessage(inbox)

        case = Case.getCurrentCase().getSleuthkitCase()
        fileManager = Case.getCurrentCase().getServices().getFileManager()
        files = fileManager.findFiles(dataSource, "%", "/")
        caseDir = Case.getCurrentCase().getModulesOutputDirAbsPath()
        tempDir = Case.getCurrentCase().getTempDirectory()

        connection = None
        numFiles = 0

        dllDumpDir = caseDir + "\VolatilityProcessor\\Dump_Files\\DLLDump"
        dumpRegistryDir = caseDir + "\VolatilityProcessor\\Dump_Files\\RegistryDump"
        procDumpDir = caseDir + "\VolatilityProcessor\\Dump_Files\\ProcDump"
        hiveDumpDir = caseDir + "\VolatilityProcessor\\HiveDump"

        try:
            os.mkdir(caseDir + "\VolatilityProcessor")
            os.mkdir(caseDir + "\VolatilityProcessor\\Dump_Files")
            os.mkdir(dllDumpDir)
            os.mkdir(dumpRegistryDir)
            os.mkdir(procDumpDir)
            os.mkdir(hiveDumpDir)
        except OSError as e:
            self.log(Level.WARNING, logHeader + "Trying to create directory that already exists: " + e.message)

        self.log(Level.INFO, logHeader + "Case directory: " + caseDir)

        # Verifying
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Verifying files")
        IngestServices.getInstance().postMessage(inbox)
        progressBar.progress("Verifying files")
        validMessage = "<p>Valid Files</p><ul>"
        validFiles = ""
        invalidFiles = ""
        invalidList = []
        cannotValidateMessage = ""
        for file in files:
            imageFilePath = file.getLocalAbsPath()
            if imageFilePath is not None:
                fileName = os.path.basename(imageFilePath)
                containingFolder = os.path.dirname(imageFilePath)
                self.log(Level.INFO, logHeader + "Containing directory of file: " + containingFolder)
                self.log(Level.INFO, logHeader + "Copying file to temp dir")
                inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                                    "Making copy of " + fileName)
                IngestServices.getInstance().postMessage(inbox)
                copyfile(imageFilePath, tempDir + "\\" + fileName)
                copiedFilePath = tempDir + "\\" + fileName
                self.log(Level.INFO, logHeader + "Verifying " + fileName)

                hashFile = fileName[:-4] + ".Hash.txt"
                hashFilePath = containingFolder + "\\" + hashFile
                self.log(Level.INFO, logHeader + "Filename containing verification hash: " + hashFile)
                if os.path.exists(copiedFilePath):
                    fileHash = ""
                    md5 = hashlib.md5()
                    with open(copiedFilePath, "rb") as fileToValidate:
                        fileChunk = fileToValidate.read(BLOCKSIZE)
                        while len(fileChunk) > 0:
                            md5.update(fileChunk)
                            fileChunk = fileToValidate.read(BLOCKSIZE)
                        fileHash = md5.hexdigest()
                    self.log(Level.INFO, logHeader + "File hash for " + fileName + ": " + fileHash)

                    with open(hashFilePath, "r") as verificationFile:
                        verificationHash = verificationFile.readline().decode("ascii", "ignore")
                        if verificationHash == fileHash:
                            self.log(Level.INFO, logHeader + fileName + " has been verified")
                            validFiles += "<li>" + fileName + "</li>"
                            numFiles += 1
                        else:
                            self.log(Level.WARNING, logHeader + fileName + " is invalid")
                            self.log(Level.INFO, logHeader + "verification file hash: " + verificationHash)
                            invalidFiles += "<li>" + fileName + "</li>"
                            invalidFiles += "<ul><li>Computed hash: " + fileHash + "</li><li>Hash in verification file: " + \
                                            verificationHash + "</li></ul>"
                            invalidList.append(fileName)
                else:
                    self.log(Level.WARNING, logHeader + "Verification file does not exist")
                    cannotValidateMessage += "<li>" + fileName + "</li>"
                    invalidList.append(fileName)

        validMessage += validFiles + "</ul><p>Invalid files</p><ul>" + invalidFiles + \
                        "</ul><p>Cannot validate due to missing validation file</p><ul>" + cannotValidateMessage + "</ul>"
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Verifying files result", validMessage)
        IngestServices.getInstance().postMessage(inbox)

        # Processing
        self.processCount = 10
        progressBar.switchToDeterminate(self.progressCount(self.processCount, numFiles))
        VolatilityService = VolatilityServiceClass(self.VolatilityDir, self.Profile)
        currentFile = 1
        for file in files:
            currentProcess = 1
            imageFilePath = file.getLocalAbsPath()
            if imageFilePath is not None:
                containingFolder = os.path.dirname(imageFilePath)
                fileName = os.path.basename(imageFilePath)
                if fileName not in invalidFiles:
                    dbName = caseDir + "\\VolatilityProcessor\\" + fileName[:-4] + ".db3"
                    passwordFile = caseDir + "\\VolatilityProcessor\\" + fileName[:-4] + "-PASSWORD.txt"

                    if not os.path.isfile(dbName):
                        self.log(Level.WARNING, logHeader + "Database file " + dbName + " does not exist")

                    VolatilityService.setDbName(dbName)

                    inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                                        "Analysing memory for " + fileName)
                    IngestServices.getInstance().postMessage(inbox)

                    self.log(Level.INFO, logHeader + "Database: " + dbName)
                    filePathToProcess = tempDir + "\\" + fileName

                    # Hivelist
                    progressBar.progress("Running hivelist", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "File to process: " + filePathToProcess)
                    self.log(Level.INFO, logHeader + "Running hivelist...")
                    pipe = VolatilityService.hivelist(filePathToProcess)
                    result = pipe.communicate()
                    self.log(Level.INFO, logHeader + "Hivelist result: " + str(result))

                    # Psscan
                    progressBar.progress("Running psscan", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running psscan...")
                    pipe = VolatilityService.psscan(filePathToProcess)
                    self.log(Level.INFO, logHeader + "Psscan result: " + str(pipe.communicate()))

                    # Pslist
                    progressBar.progress("Running pslist", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running pslist...")
                    pipe = VolatilityService.pslist(filePathToProcess)
                    self.log(Level.INFO, logHeader + "Pslist result: " + str(pipe.communicate()))

                    # Filescan
                    progressBar.progress("Running filescan", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running filescan...")
                    pipe = VolatilityService.filescan(filePathToProcess)
                    self.log(Level.INFO, logHeader + "Filescan results: " + str(pipe.communicate()))

                    # Netscan
                    progressBar.progress("Running netscan", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running netscan...")
                    pipe = VolatilityService.netscan(filePathToProcess)
                    self.log(Level.INFO, logHeader + "Netscan results: " + str(pipe.communicate()))

                    # Hashdump
                    try:
                        Class.forName("org.sqlite.JDBC").newInstance()
                        connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)
                    except SQLException as e:
                        self.log(Level.INFO, "Could not open database file (not SQLite) " + dbName + " (" + e.getMessage() + ")")
                        return IngestModule.ProcessResult.ERROR

                    systemVirtualAddress = None
                    samVirtualAddress = None

                    try:
                        statement1 = connection.createStatement()
                        statement2 = connection.createStatement()
                        resultSet1 = statement1.executeQuery("SELECT Virtual FROM HiveList WHERE Name LIKE '%SYSTEM'")
                        resultSet2 = statement2.executeQuery("SELECT Virtual FROM HiveList WHERE Name LIKE '%SAM'")
                        if resultSet1.next():
                            systemVirtualAddress = resultSet1.getString("Virtual")

                        if resultSet2.next():
                            samVirtualAddress = resultSet2.getString("Virtual")

                        resultSet1.close()
                        resultSet2.close()
                        statement1.close()
                        statement2.close()
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())
                        # return IngestModule.ProcessResult.ERROR
                    progressBar.progress("Running hashdump", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running hashdump...")
                    pipe = VolatilityService.getPasswords(filePathToProcess, systemVirtualAddress, samVirtualAddress, passwordFile)
                    result = pipe.communicate()
                    self.log(Level.INFO, logHeader + "Hashdump result: " + str(result))

                    # Hivedump
                    try:
                        statement = connection.createStatement()
                        resultset = statement.executeQuery("SELECT Virtual FROM HiveList")
                        virtualAddresses = []
                        while resultset.next():
                            virtualAddresses.append(resultset.getString("Virtual"))

                        resultset.close()
                        statement.close()
                        connection.close()

                        progressBar.progress("Running hivedump", self.progressCount(currentProcess, currentFile))
                        currentProcess += 1

                        self.log(Level.INFO, logHeader + "Running hivedump for registries")
                        self.log(Level.INFO, logHeader + "Number of addresses to dump: " + str(len(virtualAddresses)))
                        addressNum = 1
                        for address in virtualAddresses:
                            self.log(Level.INFO, logHeader + "Running address number: " + str(addressNum))
                            pipe = VolatilityService.hivedump(filePathToProcess, address, hiveDumpDir + "\\" + str(address) + ".json")
                            self.log(Level.INFO, logHeader + "Hivedump result: " + str(pipe.communicate()))
                            addressNum += 1
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())
                        # return IngestModule.ProcessResult.ERROR
                    try:
                        Class.forName("org.sqlite.JDBC").newInstance()
                        connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)

                        statement = connection.createStatement()
                        result = statement.executeQuery("SELECT COUNT(name) AS NumTables FROM sqlite_master WHERE name LIKE 'HiveDump'")
                        numTables = result.getInt("NumTables")
                        if numTables == 0:
                            try:
                                preparedStatement = connection.prepareStatement("CREATE TABLE HiveDump ([Offset(V)] TEXT, LastWritten TEXT, Key TEXT)")
                                preparedStatement.executeUpdate()
                            except SQLException as ex:
                                self.log(Level.WARNING, logHeader + "Error creating HiveDump: " + ex.getMessage())

                        for hiveDumpFile in os.listdir(hiveDumpDir):
                            if hiveDumpFile.endswith(".json"):
                                hiveDumpFileName = os.path.basename(hiveDumpFile)
                                offset = os.path.splitext(hiveDumpFileName)[0]
                                with open(hiveDumpDir + "\\" + hiveDumpFileName, "r") as hiveDump:
                                    for line in hiveDump:
                                        result = json.loads(line)
                                        for item in result["rows"]:
                                            lastWritten = item[0]
                                            key = item[1]

                                            preparedStatement = connection.prepareStatement("INSERT INTO HiveDump ([Offset(V)], LastWritten, Key) "
                                                                                            "VALUES (?, ?, ?)")
                                            preparedStatement.setString(1, offset)
                                            preparedStatement.setString(2, lastWritten)
                                            preparedStatement.setString(3, key)
                                            preparedStatement.executeUpdate()
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot insert into HiveDump table: " + ex.getMessage())
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())
                        # return IngestModule.ProcessResult.ERROR

                    # Dlldump
                    progressBar.progress("Running dlldump", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running dlldump...")
                    pipe = VolatilityService.dlldump(filePathToProcess, dllDumpDir)
                    self.log(Level.INFO, logHeader + "Dlldump results: " + str(pipe.communicate()))

                    # Dumpregistry
                    progressBar.progress("Running dumpregistry", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running dumpregistry...")
                    pipe = VolatilityService.dumpregistry(filePathToProcess, dumpRegistryDir)
                    self.log(Level.INFO, logHeader + "Dumpregistry results: " + str(pipe.communicate()))

                    # Procdump
                    try:
                        progressBar.progress("Running procdump", self.progressCount(currentProcess, currentFile))
                        currentProcess += 1

                        Class.forName("org.sqlite.JDBC").newInstance()
                        connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)

                        statement = connection.createStatement()
                        resultset1 = statement.executeQuery("SELECT DISTINCT PID FROM PSList")
                        pids = []
                        while resultset1.next():
                            pids.append(resultset1.getString("PID"))

                        resultset1.close()
                        statement.close()
                        connection.close()

                        self.log(Level.INFO, logHeader + "Number of unique processes to dump: " + str(len(pids)))
                        pipe = VolatilityService.procdump(filePathToProcess, pids, procDumpDir)
                        self.log(Level.INFO, logHeader + "Procdump result: " + str(pipe.communicate()))
                    except SQLException as ex:
                            self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())
                            # return IngestModule.ProcessResult.ERROR

                    # Analyse
                    inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                                        "Analysing results for " + fileName)
                    IngestServices.getInstance().postMessage(inbox)

                    progressBar.progress("Analysing results", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1

                    try:
                        Class.forName("org.sqlite.JDBC").newInstance()
                        connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)

                        processArtifactName = ""
                        registryArtifactName = ""
                        accountArtifactName = ""
                        fileArtifactName = ""

                        try:
                            processArtifactName = "VolatilityProcessor_Processes_" + fileName
                            registryArtifactName = "VolatilityProcessor_Registries_" + fileName
                            accountArtifactName = "VolatilityProcessor_Accounts_" + fileName
                            fileArtifactName = "VolatilityProcessor_Files_" + fileName

                            case.addArtifactType(processArtifactName, processArtifactName)
                            case.addArtifactType(registryArtifactName, registryArtifactName)
                            case.addArtifactType(accountArtifactName, accountArtifactName)
                            case.addArtifactType(fileArtifactName, fileArtifactName)
                        except:
                            self.log(Level.WARNING, logHeader + "Error creating artifacts, some artifacts might not exist")

                        processArtifact = case.getArtifactTypeID(processArtifactName)
                        processArtifactType = case.getArtifactType(processArtifactName)
                        registryArtifact = case.getArtifactTypeID(registryArtifactName)
                        registryArtifactType = case.getArtifactType(registryArtifactName)
                        accountArtifact = case.getArtifactTypeID(accountArtifactName)
                        accountArtifactType = case.getArtifactType(accountArtifactName)
                        fileArtifact = case.getArtifactTypeID(fileArtifactName)
                        fileArtifactType = case.getArtifactType(fileArtifactName)

                        # Account
                        try:
                            case.addArtifactAttributeType(accountArtifactName,
                                                      BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                      "Account Hash")
                        except:
                            self.log(Level.WARNING, logHeader + "Attribute already added: " + accountArtifactName)
                        art = file.newArtifact(accountArtifact)
                        accountAttribute = case.getAttributeType(accountAttribute)
                        with open(passwordFile, "r") as accountFile:
                            for line in accountFile:
                                art.addAttribute(BlackboardAttribute(accountAttribute, VolatilityIngestModuleFactory.moduleName, line))

                        # Process
                        try:
                            statement = connection.createStatement()
                            resultSet = statement.executeQuery("SELECT DISTINCT "
                                                               "p.PID, "
                                                               "p.Name, "
                                                               "p.PPID, "
                                                               "p.[Offset(V)], "
                                                               "n.LocalAddr, "
                                                               "n.ForeignAddr, "
                                                               "n.State, "
                                                               "n.Created, "
                                                               "p.[Time Created] AS [Process Time Created], "
                                                               "p.[Time Exited] AS [Process Time Exited] "
                                                               "FROM PSScan p "
                                                               "LEFT JOIN Netscan n ON n.[PID] = p.[PID]")

                            try:
                                case.addArtifactAttributeType(processArtifactName + "_PID",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "PID")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_PID")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_Name",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Name")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_Name")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_PPID",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "PPID")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_PPID")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_Offset",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Offset Virtual")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_Offset")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_LocalAddr",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Local Address")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_LocalAddr")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_ForeignAddr",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Foreign Address")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_ForeignAddr")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_State",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "State")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_State")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_Created",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Created")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_Created")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_ProcessTimeCreated",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Process Time Created")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_ProcessTimeCreated")
                            try:
                                case.addArtifactAttributeType(processArtifactName + "_ProcessTimeExited",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Process Time Exited")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + processArtifactName + "_ProcessTimeExited")

                            pid = case.getAttributeType(processArtifactName + "_PID")
                            name = case.getAttributeType(processArtifactName + "_Name")
                            ppid = case.getAttributeType(processArtifactName + "_PPID")
                            offset = case.getAttributeType(processArtifactName + "_Offset")
                            local = case.getAttributeType(processArtifactName + "_LocalAddr")
                            foreign = case.getAttributeType(processArtifactName + "_ForeignAddr")
                            state = case.getAttributeType(processArtifactName + "_State")
                            created = case.getAttributeType(processArtifactName + "_Created")
                            pcreated = case.getAttributeType(processArtifactName + "_ProcessTimeCreated")
                            pexited = case.getAttributeType(processArtifactName + "_ProcessTimeExited")

                            while resultSet.next():
                                proc = file.newArtifact(processArtifact)
                                proc.addAttribute(BlackboardAttribute(pid,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("PID")))
                                proc.addAttribute(BlackboardAttribute(name,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Name")))
                                proc.addAttribute(BlackboardAttribute(ppid,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("PPID")))
                                proc.addAttribute(BlackboardAttribute(offset,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Offset(V)")))
                                proc.addAttribute(BlackboardAttribute(local,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("LocalAddr")))
                                proc.addAttribute(BlackboardAttribute(foreign,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("ForeignAddr")))
                                proc.addAttribute(BlackboardAttribute(state,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("State")))
                                proc.addAttribute(BlackboardAttribute(created,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Created")))
                                proc.addAttribute(BlackboardAttribute(pcreated,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Process Time Created")))
                                proc.addAttribute(BlackboardAttribute(pexited,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Process Time Exited")))

                                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(VolatilityIngestModuleFactory.moduleName,
                                                                                 processArtifactType, None))

                            resultSet.close()
                            statement.close()

                        except SQLException as ex:
                            self.log(Level.SEVERE, logHeader + "Cannot continue analysis due to database errors: " + ex.getMessage())

                        #     Registry
                        try:
                            statement = connection.createStatement()
                            resultSet = statement.executeQuery("SELECT "
                                                               "l.Virtual,"
                                                               "l.Name AS RegistryName, "
                                                               "l.Physical, "
                                                               "k.Key, "
                                                               "k.LastWritten "
                                                               "FROM HiveList l "
                                                               "INNER JOIN HiveDump k ON k.[Offset(V)] = l.Virtual")

                            try:
                                case.addArtifactAttributeType(registryArtifactName + "_Virtual",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Virtual Address")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + registryArtifactName + "_Virtual")
                            try:
                                case.addArtifactAttributeType(registryArtifactName + "_Physical",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Physical Address")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + registryArtifactName + "_Physical")
                            try:
                                case.addArtifactAttributeType(registryArtifactName + "_Name",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Registry Name")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + registryArtifactName + "_Name")
                            try:
                                case.addArtifactAttributeType(registryArtifactName + "_Key",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Key")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + registryArtifactName + "_Key")
                            try:
                                case.addArtifactAttributeType(registryArtifactName + "_LastWritten",
                                                          BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING,
                                                          "Last Written")
                            except:
                                self.log(Level.WARNING, logHeader + "Attribute already added: " + registryArtifactName + "_LastWritten")

                            virtual = case.getAttributeType(registryArtifactName + "_Virtual")
                            physical = case.getAttributeType(registryArtifactName + "_Physical")
                            name = case.getAttributeType(registryArtifactName + "_Name")
                            key = case.getAttributeType(registryArtifactName + "_Key")
                            last = case.getAttributeType(registryArtifactName + "_LastWritten")

                            while resultSet.next():
                                reg = file.newArtifact(registryArtifact)
                                reg.addAttribute(BlackboardAttribute(virtual,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Virtual")))
                                reg.addAttribute(BlackboardAttribute(physical,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Physical")))
                                reg.addAttribute(BlackboardAttribute(name,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("RegistryName")))
                                reg.addAttribute(BlackboardAttribute(key,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("Key")))
                                reg.addAttribute(BlackboardAttribute(last,
                                                                      VolatilityIngestModuleFactory.moduleName,
                                                                      resultSet.getString("LastWritten")))

                                IngestServices.getInstance().fireModuleDataEvent(ModuleDataEvent(VolatilityIngestModuleFactory.moduleName,
                                                                                 registryArtifactType, None))
                        except SQLException as ex:
                            self.log(Level.SEVERE, logHeader + "Cannot continue analysis due to database errors: " + ex.getMessage())

                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot open database due to database errors: " + ex.getMessage())

                    if connection is not None:
                        try:
                            connection.close()
                        except SQLException as e:
                            self.log(Level.WARNING, logHeader + "Could not close database: " + e.getMessage())

                    currentFile += 1

        return IngestModule.ProcessResult.OK

    def shutDown(self):
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Volatiity Process Stopped")
        IngestServices.getInstance().postMessage(inbox)

        self.log(Level.INFO, "Volatility Processor Finished")



class VolatilityIngestModuleSettings(IngestModuleIngestJobSettings):
    def __init__(self):
        self.versionUID = 1L
        self.VolatilityDir = ""
        self.Version = "2.5"
        self.Profile = "Autodetect"

    # Getters and setters
    def getVersionUID(self):
        return self.versionUID

    def getVolatilityDir(self):
        return self.VolatilityDir

    def getVersion(self):
        return self.Version

    def getProfile(self):
        return self.Profile

    def setVolatilityDir(self, dir):
        self.VolatilityDir = dir

    def setVersion(self, version):
        self.Version = version

    def setProfile(self, profile):
        self.Profile = profile
