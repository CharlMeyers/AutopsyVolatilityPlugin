import inspect
import os
import hashlib
import time
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
from java.lang import System
from java.lang import Exception

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
    processCount = 5
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
        numFiles = 0
        try:
            os.mkdir(caseDir + "\VolatilityProcessor")
        except OSError:
            self.log(Level.WARNING, logHeader + "VolatilityProcessor directory already exists")
        connection = None

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
        # for file in files:
        #     imageFilePath = file.getLocalAbsPath()
        #     if imageFilePath is not None:
        #         fileName = os.path.basename(imageFilePath)
        #         containingFolder = os.path.dirname(imageFilePath)
        #         self.log(Level.INFO, logHeader + "Containing directory of file: " + containingFolder)
        #         self.log(Level.INFO, logHeader + "Verifying " + fileName)
        #
        #         hashFile = fileName[:-4] + ".Hash.txt"
        #         hashFilePath = containingFolder + "\\" + hashFile
        #         self.log(Level.INFO, logHeader + "Filename containing verification hash: " + hashFile)
        #         if os.path.exists(hashFilePath):
        #             fileHash = ""
        #             md5 = hashlib.md5()
        #             with open(imageFilePath, "rb") as fileToValidate:
        #                 fileChunk = fileToValidate.read(BLOCKSIZE)
        #                 while len(fileChunk) > 0:
        #                     md5.update(fileChunk)
        #                     fileChunk = fileToValidate.read(BLOCKSIZE)
        #                 fileHash = md5.hexdigest()
        #             self.log(Level.INFO, logHeader + "File hash for " + fileName + ": " + fileHash)
        #
        #             with open(hashFilePath, "r") as verificationFile:
        #                 verificationHash = verificationFile.readline().decode("ascii", "ignore")
        #                 if verificationHash == fileHash:
        #                     self.log(Level.INFO, logHeader + fileName + " has been verified")
        #                     validFiles += "<li>" + fileName + "</li>"
        #                     numFiles += 1
        #                 else:
        #                     self.log(Level.WARNING, logHeader + fileName + " is invalid")
        #                     self.log(Level.INFO, logHeader + "verification file hash: " + verificationHash)
        #                     invalidFiles += "<li>" + fileName + "</li>"
        #                     invalidFiles += "<ul><li>Computed hash: " + fileHash + "</li><li>Hash in verification file: " + \
        #                                     verificationHash + "</li></ul>"
        #                     invalidList.append(fileName)
        #         else:
        #             self.log(Level.WARNING, logHeader + "Verification file does not exist")
        #             cannotValidateMessage += "<li>" + fileName + "</li>"
        #             invalidList.append(fileName)

        validMessage += validFiles + "</ul><p>Invalid files</p><ul>" + invalidFiles + \
                        "</ul><p>Cannot validate due to missing validation file</p><ul>" + cannotValidateMessage + "</ul>"
        inbox = IngestMessage.createMessage(IngestMessage.MessageType.INFO, "Volatility Processor",
                                            "Verifying files result", validMessage)
        IngestServices.getInstance().postMessage(inbox)

        # Processing
        numFiles = 1 # TODO: remove this line
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
                    passwordFile = caseDir + "\\VolatilityProcessor\\" + fileName[:-4] + ".txt"
                    if not os.path.isfile(dbName):
                        self.log(Level.WARNING, logHeader + "Database file " + dbName + " does not exist")
                    else:
                        self.log(Level.INFO, logHeader + "The file does exist")
                    VolatilityService.setDbName(dbName)
                    self.log(Level.INFO, logHeader + "Database: " + dbName)
                    filePathToProcess = containingFolder + "/" + fileName
                    progressBar.progress("Hivelist", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1

                    self.log(Level.INFO, logHeader + "File to process: " + filePathToProcess)
                    self.log(Level.INFO, logHeader + "Running hivescan...")
                    # pipe = VolatilityService.hivescan(filePathToProcess)
                    # result = pipe.communicate()
                    # self.log(Level.INFO, logHeader + "Hivelist result: " + str(result))
                    progressBar.progress("Scanning for processes", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1

                    # self.log(Level.INFO, logHeader + "Running psscan...")
                    # pipe = VolatilityService.psScan(filePathToProcess)
                    # self.log(Level.INFO, logHeader + "Psscan result: " + str(pipe.communicate()))

                    # try:
                    #     Class.forName("org.sqlite.JDBC").newInstance()
                    #     connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)
                    # except SQLException as e:
                    #     self.log(Level.INFO, "Could not open database file (not SQLite) " + dbName + " (" + e.getMessage() + ")")
                    #     return IngestModule.ProcessResult.OK

                    # systemVirtualAddress = None
                    # samVirtualAddress = None
                    #
                    # try:
                    #     statement1 = connection.createStatement()
                    #     statement2 = connection.createStatement()
                    #     resultSet1 = statement1.executeQuery("SELECT Virtual FROM HiveList WHERE Name LIKE '%SYSTEM'")
                    #     resultSet2 = statement2.executeQuery("SELECT Virtual FROM HiveList WHERE Name LIKE '%SAM'")
                    #     if resultSet1.next():
                    #         systemVirtualAddress = resultSet1.getString("Virtual")
                    #
                    #     if resultSet2.next():
                    #         samVirtualAddress = resultSet2.getString("Virtual")
                    #
                    #     resultSet1.close()
                    #     resultSet2.close()
                    #     statement1.close()
                    #     statement2.close()
                    # except SQLException as ex:
                    #     self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())
                    # progressBar.progress("Scanning for passwords", self.progressCount(currentProcess, currentFile))
                    # currentProcess += 1
                    # self.log(Level.INFO, logHeader + "Running hashdump...")
                    # pipe = VolatilityService.getPasswords(filePathToProcess, systemVirtualAddress, samVirtualAddress, passwordFile)
                    # result = pipe.communicate()
                    # self.log(Level.INFO, logHeader + "Hashdump result: " + str(result))
                    try:
                        # statement = connection.createStatement()
                        # resultset = statement.executeQuery("SELECT Virtual FROM HiveList")
                        # virtualAddresses = []
                        # while resultset.next():
                        #     virtualAddresses.append(resultset.getString("Virtual"))
                        #
                        # resultset.close()
                        # statement.close()
                        # connection.close()

                        progressBar.progress("Making hive dump", self.progressCount(currentProcess, currentFile))
                        currentProcess += 1

                        # self.log(Level.INFO, logHeader + "Running hivedump for registries")
                        # self.log(Level.INFO, logHeader + "Number of addresses to dump: " + str(len(virtualAddresses)))
                        # addressNum = 1
                        # for address in virtualAddresses:
                        #     self.log(Level.INFO, logHeader + "Running address number: " + str(addressNum))
                        #     pipe = VolatilityService.printkey(filePathToProcess, address)
                        #     self.log(Level.INFO, logHeader + "Hivedump result: " + str(pipe.communicate()))
                        #     addressNum += 1
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())

                    try:
                        # self.log(Level.INFO, logHeader + "Connecting to db")
                        # Class.forName("org.sqlite.JDBC").newInstance()
                        # connection = DriverManager.getConnection("jdbc:sqlite:/%s" % dbName)
                        # self.log(Level.INFO, logHeader + "Running statement")
                        # statement1 = connection.createStatement()
                        # resultset1 = statement.executeQuery("SELECT Key FROM HiveDump")
                        # keys = []
                        # while resultset1.next():
                        #     keys.append(resultset1.getString("Key"))
                        #
                        # resultset1.close()
                        # statement1.close()
                        # connection.close()

                        # self.log(Level.INFO, logHeader + "Number of keys to print: " + str(len(keys)))
                        progressBar.progress("Printing keys", self.progressCount(currentProcess, currentFile))
                        currentProcess += 1

                        self.log(Level.INFO, logHeader + "Running Printkey...")
                        # for key in keys:
                        #     self.log(Level.INFO, logHeader + "Printing key: " + key)
                        #     pipe = VolatilityService.printkey(filePathToProcess, key)
                        #     self.log(Level.INFO, logHeader + "Printkey result: " + str(pipe.communicate()))
                    except SQLException as ex:
                        self.log(Level.SEVERE, logHeader + "Cannot continue scan due to database errors: " + ex.getMessage())

                    progressBar.progress("Running netscan", self.progressCount(currentProcess, currentFile))
                    currentProcess += 1
                    self.log(Level.INFO, logHeader + "Running netscan...")
                    pipe = VolatilityService.netScan(filePathToProcess)
                    self.log(Level.INFO, logHeader + "Netscan results: " + str(pipe.communicate()))

                # if connection is not None:
                #     connection.close()

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
