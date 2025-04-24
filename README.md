# pcConfig
## Collection of powershell scripts for the automatic configuration, management and control of lab PCs.

## Tools include:

### pcConfig
    autoconfigure the PC for laboratory use
    disable: screensaver, user switching, lock PC and other common settings 
    set permissions for the automation script operation and deployment
    install required powershell modules
    create logoff button on desktop

### ppmsConfig
    Requires the Stratocore PPMS booking platform
    Autodetection and installation of PPMS system parameters based on PC name (with manual override)
    Configuration settings for subsequent scripts
<br>![Script Settings](https://github.com/user-attachments/assets/dd53e04f-78c2-49e8-bef5-a3540c9901f6)<br>

    
### wallpaper
    Install custom desktop wallpaper
    Automatic installation of custom desktop wallpapers based on instrument name/type

### announcement
    Facility announcements and questionaires
    Create customised one-off, repeating, random announcements from a webpage and display on instrument pcs
<br>![Announcements](https://github.com/user-attachments/assets/88981e1d-56eb-46ff-96b8-df5022d8a73a)<br>
<br>![Questionaire](https://github.com/user-attachments/assets/a1eb55a9-185c-46f7-bbaa-f683b6f86de9)<br>


### autoDeleteFiles
    Configurable Autodeletion of files by location, age and filetype to manage multiple HDD space
    reporting to admin via email/slack/teams when storage cant be cleared
    
### controlPanel
    Requires the Stratocore PPMS booking platform
    PPMS control panel (report incidents, quick book, current and next session info, email alerts etc)
  ![Control Panel](https://github.com/user-attachments/assets/940d0543-16a2-4c9b-8b54-1d9de19642f1)
  
  ![Control Panel 2](https://github.com/user-attachments/assets/ab487985-0753-4749-80dc-b6ad8d6f4ed2)

    
### googleSoftwareTracker
    Track and report multiple simultaneous software use to google sheets
    Track remote vs local logins
    Gather PC hardware configuration and usage stats
    configurable via webpage table
<br>![Software tracker](https://github.com/user-attachments/assets/6db99d9d-c3c1-4af4-9d91-db1b92206ff5)<br>
<br>![google sheet](https://github.com/user-attachments/assets/53ebe704-411c-4290-bcad-d0cd6b29d0e2)<br>


### logoffScript
    Requires the Stratocore PPMS booking platform
    Logoff user automatically based on configurable logoff parameters 
    Allow pre- and post booking usage
    Email alerts
    Quick extend bookings
    report incidents
    easy logoff buttons with contextual notifications based on system type
    <br>
  ![logoff Panel](https://github.com/user-attachments/assets/3f09e6ad-bebe-4697-8ff7-b9ac67bf6b9b)
  <br>
  ![Logoff Panel 2](https://github.com/user-attachments/assets/eb0c0948-4aee-4426-997a-a6ff8a08eb7c)
  <br>
  ![Email Panel](https://github.com/user-attachments/assets/892bb479-363b-4b92-9304-b2d9515c0b0b)
  <br>
  ![Incident Panel](https://github.com/user-attachments/assets/49927a43-60b4-44bf-a69c-221a75cf7d68)
  <br>

### ppmsTracker
    Requires the Stratocore PPMS booking platform
    Track and report user login to PPMS
    
### validateUser
    Requires the Stratocore PPMS booking platform
    Validate user at logon
    confirms the user is active and exists in PPMS, else notifies them and logoffs off
    reports denied access to admin email/slack/teams

      
## The scripts require the following:
    Stratocore PPMS booking software, including the following custom reports as used by IMB Microscopy facility (contact Stratocore PPMS to generate these reports for your facility)
    List of systems with ID and tracker code
    Currently running not booked session
    Projects for User
<br>![Projects for User](https://github.com/user-attachments/assets/3026294e-0ba8-4fb1-af4a-d62220cc9e06)<br>
<br>![Currently running not booked session](https://github.com/user-attachments/assets/97012fc2-fb31-4c3f-9240-420572b226d0)<br>
<br>![List of Systems](https://github.com/user-attachments/assets/fcc7ddb6-57d3-4c4b-9195-245f10492445)<br>
<br>

