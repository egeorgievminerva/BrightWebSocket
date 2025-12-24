' Logger.brs
' Copyright (C) 2018 Rolando Islas
' Released under the MIT license
'
' Internal logging utility

' Initialize a logging utility
function Logger(tag as string) as object
    log = {}
    log.tag = tag
    log.FATAL = -2
    log.WARN = -1
    log.INFO = 0
    log.DEBUG = 1
    log.EXTRA = 2
    log.VERBOSE = 3

    ' Main

    ' Log a message
    ' @param level log level string or integer
    ' @param tag first part of the message
    ' @param msg optional second part of the message to print
    log.printl = sub(level as object, tag as string, msg = invalid as dynamic) as void
        if level > m.log_level
            return
        end if
        if msg = invalid
            msg = tag
            tag = m.tag
        end if
        print m._curent_timestamp() + "[" + m._level_to_string(level) + "] " + tag + ": " + msg
    end sub

    ' Parse level to a string
    ' @param level string or integer level
    log._level_to_string = function(level as object) as string
        if type(level) = "roString" or type(level) = "String"
            level = m._parse_level(level)
        end if
        if level = -2
            return "FATAL"
        else if level = -1
            return "WARN"
        else if level = 0
            return "INFO"
        else if level = 1
            return "DEBUG"
        else if level = 2
            return "EXTRA"
        else
            return "VERBOSE"
        end if
    end function

    ' Parse level to an integer
    ' @param level string or integer level
    log._parse_level = function(level as object) as integer
        level_string = level.toStr()
        log_level = 0
        if level_string = "FATAL" or level_string = "-2"
            log_level = m.FATAL
        else if level_string = "WARN" or level_string = "-1"
            log_level = m.WARN
        else if level_string = "INFO" or level_string = "0"
            log_level = m.INFO
        else if level_string = "DEBUG" or level_string = "1"
            log_level = m.DEBUG
        else if level_string = "EXTRA" or level_string = "2"
            log_level = m.EXTRA
        else if level_string = "VERBOSE" or level_string = "3"
            log_level = m.VERBOSE
        end if
        return log_level
    end function

    ' Set the log level
    log.set_log_level = sub(level as string) as void
        m.log_level = m._parse_level(level)
    end sub

    log._date_time_object = CreateObject("roDateTime")
    log._curent_timestamp = function() as string
        dateTime = m._date_time_object
        dateTime.Mark()
        dateTime.ToLocalTime()

        hours = dateTime.GetHours().ToStr("%02d")
        minutes = dateTime.GetMinutes().ToStr("%02d")
        seconds = dateTime.GetSeconds().ToStr("%02d")
        milliseconds = dateTime.GetMilliseconds().ToStr("%03d")

        return "[" + hours + ":" + minutes + ":" + seconds + "." + milliseconds + "]"
    end function

    log.log_level = log.VERBOSE
    return log
end function
