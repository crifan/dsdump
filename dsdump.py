
# Function: Optimized dsdump, extract dsdump to single ObjC and swift files
# Author: Crifan Li
# Update: 20250101
# Usage
#   python3 dsdump.py -d -i inputMachOFile -o outputFolder

import getopt
import os
import subprocess
import sys
import re

import logging
from libs.crifan import crifanLogging
from datetime import datetime,timedelta
import codecs
import json

################################################################################
# Global Variable
################################################################################

gOutputFoler = None
gOutputFoler_objc = None
gOutputFoler_objc_protocol = None
gOutputFoler_objc_class = None
gOutputFoler_objc_category = None
gOutputFoler_swift = None
gOutputFoler_swift_protocol = None
gOutputFoler_swift_class = None

################################################################################
# Util Function
################################################################################

def createFolder(folderFullPath):
    """
        create folder, even if already existed
        Note: for Python 3.2+
    """
    os.makedirs(folderFullPath, exist_ok=True)

def saveTextToFile(fullFilename, text, fileEncoding="utf-8"):
    """save text content into file"""
    with codecs.open(fullFilename, 'w', encoding=fileEncoding) as fp:
        fp.write(text)
        fp.close()

def saveJsonToFile(fullFilename, jsonValue, indent=2, fileEncoding="utf-8"):
    """
        save json dict into file
        for non-ascii string, output encoded string, without \\u xxxx
    """
    with codecs.open(fullFilename, 'w', encoding=fileEncoding) as jsonFp:
        json.dump(jsonValue, jsonFp, indent=indent, ensure_ascii=False)
        # logging.debug("Complete save json %s", fullFilename)

def getPyFolder(inputPyFile):
    """Get input python file folder == current folder

    Usage:
      curFolder = getPyFolder(__file__)

    Example:
      /xxx/parseBrJumpOffset/parseBrJumpOffset.py -> /xxx/parseBrJumpOffset/
    """
    curPyFolder = os.path.dirname(inputPyFile)
    # print("curPyFolder=%s" % curPyFolder) # curPyFolder=/xxx/parseBrJumpOffset
    curPyFolderFullPath = os.path.abspath(curPyFolder)
    # print("curPyFolderFullPath=%s" % curPyFolderFullPath) # curPyFolderFullPath=/xxx/parseBrJumpOffset
    return curPyFolderFullPath

################################################################################
# Main
################################################################################

print('''
    .         .                   
    |         |                    {Version: 2024.12.31}
 .-.| .--. .-.| .  . .--.--. .,-. 
(   | `--.(   | |  | |  |  | |   )
 `-'`-`--' `-'`-`--`-'  '  `-|`-' 
                             |    
                             '   
''')

howToUse = 'python3 dsdump.py \n -i <inputfile> \n -o <outputFolder> \n -a [ arm64 | armv7 ] \n -d'


def initOutputFolder(outputFolder):
    global gOutputFoler, gOutputFoler_objc, gOutputFoler_objc_protocol, gOutputFoler_objc_class, gOutputFoler_objc_category, gOutputFoler_swift, gOutputFoler_swift_protocol, gOutputFoler_swift_class

    # if not os.path.exists(outputFolder):
    #     os.mkdir(outputFolder)
    gOutputFoler = outputFolder
    logging.debug("gOutputFoler=%s", gOutputFoler)
    createFolder(gOutputFoler)

    curFolder = getPyFolder(__file__)
    logging.debug("curFolder=%s", curFolder)

    gOutputFoler_objc = os.path.join(gOutputFoler, "objc")
    logging.debug("gOutputFoler_objc=%s", gOutputFoler_objc)
    createFolder(gOutputFoler_objc)

    gOutputFoler_objc_protocol = os.path.join(gOutputFoler_objc, "protocol")
    createFolder(gOutputFoler_objc_protocol)
    logging.debug("gOutputFoler_objc_protocol=%s", gOutputFoler_objc_protocol)

    gOutputFoler_objc_class = os.path.join(gOutputFoler_objc, "class")
    createFolder(gOutputFoler_objc_class)
    logging.debug("gOutputFoler_objc_class=%s", gOutputFoler_objc_class)

    gOutputFoler_objc_category = os.path.join(gOutputFoler_objc, "category")
    createFolder(gOutputFoler_objc_category)
    logging.debug("gOutputFoler_objc_category=%s", gOutputFoler_objc_category)


    gOutputFoler_swift = os.path.join(gOutputFoler, "swift")
    logging.debug("gOutputFoler_swift=%s", gOutputFoler_swift)
    createFolder(gOutputFoler_swift)

    gOutputFoler_swift_protocol = os.path.join(gOutputFoler_swift, "protocol")
    createFolder(gOutputFoler_swift_protocol)
    logging.debug("gOutputFoler_swift_protocol=%s", gOutputFoler_swift_protocol)

    gOutputFoler_swift_class = os.path.join(gOutputFoler_swift, "class")
    createFolder(gOutputFoler_swift_class)
    logging.debug("gOutputFoler_swift_class=%s", gOutputFoler_swift_class)

def dumpObjc_origin(out, outputFolder, demangle):
    arr = out.split('\n\n\n')
    # saveJsonToFile("debugging/objc/arr.json", arr)
    # 分割输出内容
    protocols = arr[0].split('\n')
    classes = arr[1:-1]
    categares = arr[-1].split('\n')

    # saveJsonToFile("debugging/objc/protocols.json", protocols)
    # saveJsonToFile("debugging/objc/classes.json", classes)
    # saveJsonToFile("debugging/objc/categares.json", categares)

    # 输出protocols
    start = -1
    end = -1
    className = ''
    for i in range(len(protocols)):
        line = protocols[i]
        if '@protocol' in line:
            start = i
            className = str(line).split(' ')[1]
        if '@end' in line:
            end = i
        if start != -1 and end != -1:
            if demangle:
                out = swiftDemangle(className)
                if out != className:
                    className = out
            fileName = f'{outputFolder}/{className}.h'
            print(fileName)
            with open(fileName, mode='a') as f:
                f.write('\n'.join(protocols[start:(end + 1)]) + '\n')
                start = -1
                end = -1
    # 输出classes
    last = '\n'.join(protocols).split('@end')[-1]
    classes.append(last)
    for line in classes:
        className = line.split(' ')[1]
        if demangle:
            out = swiftDemangle(className)
            if out != className:
                className = out
        fileName = f'{outputFolder}/{className}.h'
        print(fileName)
        with open(fileName, mode='w') as f:
            f.write(line)
    # 输出categares
    count = len(categares)
    for i in range(count):
        line = categares[i]
        if line.startswith('0x00000000000'):
            continue
        if line.startswith('0x'):
            className = str(line).split(' ')[1]
            if demangle:
                out = swiftDemangle(className)
                if out != className:
                    className = out
            fileName = f'{outputFolder}/{className}.h'
            result = line + '\n'
            for j in range(i + 1, count):
                ll = categares[j]
                if ll.startswith('0x'):
                    break
                else:
                    result += ll + '\n'
            print(fileName)
            with open(fileName, mode='w') as f:
                f.write(result)

def dumpObjc_crifan_protol(out):
    global gOutputFoler_objc_protocol

    # protocolStrList = re.findall("@protocol \w+.+@end", out)
    # protocolEndP = r"@protocol \w+.+@end"
    protocolEndP = r"\@protocol (?P<protocolName>\w+).+?\@end"
    # protocolEndP = r"\@protocol (?P<protocolName>\w+).+?\@end\n*" # for debug: compare with original
    # protocolEndP = r"\@protocol \w+.+?\@end"
    logging.debug("protocolEndP=%s", protocolEndP)
    # protocolStrList = re.findall(protocolEndP, out, flags=re.DOTALL)
    protocolStrIterator = re.finditer(protocolEndP, out, flags=re.DOTALL)
    protocolStrList = list(protocolStrIterator)
    logging.debug("protocolStrList=%s", protocolStrList)

    # for eachProtocolStr in protocolStrList:
    #     logging.info("eachProtocolStr=%s", eachProtocolStr)

    for curIdx, eachProtocolMatch in enumerate(protocolStrList):
        curNum = curIdx + 1
        protocolName = eachProtocolMatch.group("protocolName")
        crifanLogging.logSingleLine(curNum, protocolName)

        logging.debug("eachProtocolMatch=%s", eachProtocolMatch)
        eachProtocolStr = eachProtocolMatch.group(0)
        logging.debug("eachProtocolStr=%s", eachProtocolStr)
        # eachProtocolContent = re.sub("\\n", "\n", eachProtocolStr)
        eachProtocolContent = eachProtocolStr
        logging.debug("eachProtocolContent=%s", eachProtocolContent)
        logging.debug("protocolName=%s", protocolName)
        protocolFilename = "%s.h" % protocolName
        logging.debug("protocolFilename=%s", protocolFilename)
        curOutputFullPath = os.path.join(gOutputFoler_objc_protocol, protocolFilename)
        # for debug
        if os.path.exists(curOutputFullPath):
            logging.debug("! existed curOutputFullPath=%s", curOutputFullPath)
        saveTextToFile(curOutputFullPath, eachProtocolContent)

    totalNum = len(protocolStrList)
    return totalNum

def dumpObjc_crifan_class(out):
    global gOutputFoler_objc_class

    # 0x0000111a090 FIRCoreDiagnostics : NSObject /usr/lib/libobjc.A.dylib <FIRCoreDiagnosticsInterop>
    # classP = r"^0x[\da-zA-Z]+ \w+ : .+"
    # classP = r"^0x[\da-zA-Z]+ \w+ : .+"
    # classP = r"^0x[\da-zA-Z]+ \w+ : .+"
    # classP = r"^0x[\da-zA-Z]+ (?P<className>\w+) : .+?\n\n\n"
    # classP = r"^0x[\da-zA-Z]+ (?P<className>\w+) : .+?\n\n"
    classP = r"^0x\w+ (?P<className>\w+) : .+?(?=\n\w+)"
    logging.debug("classP=%s", classP)
    classStrIterator = re.finditer(classP, out, flags=re.DOTALL|re.MULTILINE)
    logging.debug("classStrIterator=%s", classStrIterator)
    classStrList = list(classStrIterator)
    logging.debug("classStrList=%s", classStrList)

    for curIdx, curClassMatch in enumerate(classStrList):
        curNum = curIdx + 1
        className = curClassMatch.group("className")
        crifanLogging.logSingleLine(curNum, className)
        logging.debug("curClassMatch=%s", curClassMatch)

        curClassStr = curClassMatch.group(0)
        logging.debug("curClassStr=%s", curClassStr)
        curClassContent = curClassStr
        logging.debug("curClassContent=%s", curClassContent)
        logging.debug("className=%s", className)
        classFilename = "%s.h" % className
        logging.debug("classFilename=%s", classFilename)
        curOutputFullPath = os.path.join(gOutputFoler_objc_class, classFilename)
        saveTextToFile(curOutputFullPath, curClassContent)

    totalNum = len(classStrList)
    return totalNum

def dumpObjc_crifan_category(out):
    global gOutputFoler_objc_category

    # 0x0000106e0c8 NSError(FIRMLKit)
    categoryP = r"^0x\w+ (?P<categoryName>\w+)\((?P<parentClassName>\w+)\).+?(?=\n\w+)"
    logging.debug("categoryP=%s", categoryP)
    categoryStrIterator = re.finditer(categoryP, out, flags=re.DOTALL|re.MULTILINE)
    logging.debug("categoryStrIterator=%s", categoryStrIterator)
    categoryStrList = list(categoryStrIterator)
    logging.debug("categoryStrList=%s", categoryStrList)

    for curIdx, curCategoryMatch in enumerate(categoryStrList):
        curNum = curIdx + 1
        curCategoryStr = curCategoryMatch.group(0)
        curCategoryContent = curCategoryStr
        categoryName = curCategoryMatch.group("categoryName")
        parentClassName = curCategoryMatch.group("parentClassName")
        crifanLogging.logSingleLine(curNum, categoryName)
        logging.debug("curCategoryMatch=%s", curCategoryMatch)
        logging.debug("curCategoryStr=%s", curCategoryStr)
        logging.debug("curCategoryContent=%s", curCategoryContent)
        logging.debug("categoryName=%s", categoryName)
        logging.debug("parentClassName=%s", parentClassName)
        # categoryFilename = "%s.h" % categoryName
        categoryFilename = "%s(%s).h" % (categoryName, parentClassName)
        logging.debug("categoryFilename=%s", categoryFilename)
        curOutputFullPath = os.path.join(gOutputFoler_objc_category, categoryFilename)
        saveTextToFile(curOutputFullPath, curCategoryContent)

    totalNum = len(categoryStrList)
    return totalNum

def dumpObjc_crifan(out):
    totalNum_objc_protocol = dumpObjc_crifan_protol(out)
    totalNum_objc_class = dumpObjc_crifan_class(out)
    totalNum_objc_category = dumpObjc_crifan_category(out)
    summaryDict_objc = {
        "protocol": totalNum_objc_protocol,
        "class": totalNum_objc_class,
        "category": totalNum_objc_category,
        "total": totalNum_objc_protocol + totalNum_objc_class + totalNum_objc_category,
    }
    return summaryDict_objc

def dumpObjectiveC(inputfile, outputFolder, arches, demangle):
    strline = f'./dsdump -a {arches} --objc --verbose=5 "{inputfile}"'
    p = subprocess.Popen(strline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.communicate()[0].decode('utf-8', 'ignore')
    saveTextToFile("debugging/objc/out.coffee", out)

    # dumpObjc_origin(out, outputFolder, demangle)
    summaryDict = dumpObjc_crifan(out)
    return summaryDict

def dumpSwift_origin(out, outputFolder):
    arr = out.split('\n')
    saveJsonToFile("debugging/swift/arr.txt", arr)

    className = ''
    start = -1
    end = -1
    count = len(arr)
    for i in range(count):
        line = arr[i].strip()
        if line.startswith('class') or line.startswith('enum') or line.startswith('struct'):
            className = line.split(' ')[1].strip()
            fileName = f'{outputFolder}/{className}.swift'
            start = i
            if line.endswith('}'):
                end = i
        elif line.endswith('}'):
            end = i
        if start != -1 and end != -1:
            print(fileName)
            with open(fileName, mode='a') as f:
                f.write('\n'.join(arr[start:end + 1]) + '\n')
            start = -1
            end = -1

def dumpSwift_crifan_protocol(out):
    global gOutputFoler_swift_protocol

    """
        protocol KonaPayCore.OtpService // 2 requirements
        {
            // method
            // method
        }
    """
    protocolP = r"protocol (?P<libName>\w+)\.(?P<protocolName>\w+) // \d+ requirements\s+\{.+?\}"
    logging.debug("protocolP=%s", protocolP)
    protocolStrIterator = re.finditer(protocolP, out, flags=re.DOTALL)
    protocolStrList = list(protocolStrIterator)
    logging.debug("protocolStrList=%s", protocolStrList)

    for curIdx, eachProtocolMatch in enumerate(protocolStrList):
        curNum = curIdx + 1
        libName = eachProtocolMatch.group("libName")
        protocolName = eachProtocolMatch.group("protocolName")
        crifanLogging.logSingleLine(curNum, protocolName)
        logging.debug("libName=%s", libName)
        logging.debug("protocolName=%s", protocolName)

        logging.debug("eachProtocolMatch=%s", eachProtocolMatch)
        eachProtocolStr = eachProtocolMatch.group(0)
        logging.debug("eachProtocolStr=%s", eachProtocolStr)
        protocolFilename = "%s.%s.swift" % (libName, protocolName)
        logging.debug("protocolFilename=%s", protocolFilename)
        curOutputFullPath = os.path.join(gOutputFoler_swift_protocol, protocolFilename)

        # for debug
        if os.path.exists(curOutputFullPath):
            logging.debug("! existed curOutputFullPath=%s", curOutputFullPath)

        saveTextToFile(curOutputFullPath, eachProtocolStr)
    
    totalNum = len(protocolStrList)
    return totalNum

def dumpSwift_crifan_class(out):
    global gOutputFoler_swift_class

    """
        abnormal:
            class __C.SecKey {

        normal:

            class KonaPayCore.OtpServiceImpl : _SwiftObject @rpath/libswiftCore.dylib, OtpService {

                // Properties
                let apiGwService : ApiGwService

                // Swift methods
            }
        contain warning (and special char):
            class KonaPayCore.ApiBillerListRequest : ApiGwRequest {

                // Properties
            WARNING: couldn't find address 0x0 (0x0) in binary!
                var page : 5
            WARNING: couldn't find address 0x0 (0x0) in binary!
                var pageSize : 5
                var categoryCode : String?
                var merchantId : String?
                var status : String?
                var categoryCodeIn : String?
                var categoryCodeNotIn : String?
                var productTypeIn : String?

                // Swift methods
            }
        
        enum:
            enum KonaPayCore.TransactionSubCategory {

                // Properties
                case INTEREST  
                case KYC_COMMISSION  
                case PARTNER_DISBURSEMENT  
                case CASH_BACK  
                case GIFT  
                case REMITTANCE  
                case RECHARGE  
                case WELCOME_BONUS  
                case CARD_RECHARGE  
                case BANK_RECHARGE  
                case DPS_REDEEM  
                case INSTALMENT_VIA_AG  
                case DPS_AG_REF_BONUS  
                case DPS_CU_REF_BONUS  
                case SUBSIDIZED_FEE  
                case TRANSFER_MONEY  
            }
        
        struct:
            struct KonaPayCore.Charges {

                // Properties
                var txServiceType : TransactionServiceChargeType
                var appChargeInfo : ChargeInfo
                var ussdChargeInfo : ChargeInfo
            }

    """

    # classP = r"((class)|(enum)|(struct)) (?P<libName>\w+)\.(?P<className>\w+) .*?\{.+?\}"
    # classP = r"((class)|(enum)|(struct)) (?P<libName>\w+)\.(?P<className>\w+) .*?\{[^\{]+?\}"
    classP = r"((class)|(enum)|(struct)) (?P<libName>\w+)\.(?P<className>\w+) [^\{]*?\{[^\{]+?\}"
    logging.debug("classP=%s", classP)
    classStrIterator = re.finditer(classP, out, flags=re.DOTALL|re.MULTILINE)
    logging.debug("classStrIterator=%s", classStrIterator)
    classStrList = list(classStrIterator)
    logging.debug("classStrList=%s", classStrList)

    for curIdx, curClassMatch in enumerate(classStrList):
        curNum = curIdx + 1
        className = curClassMatch.group("className")
        libName = curClassMatch.group("libName")
        crifanLogging.logSingleLine(curNum, className)
        logging.debug("curClassMatch=%s", curClassMatch)
        logging.debug("libName=%s, className=%s", libName, className)

        curClassStr = curClassMatch.group(0)
        logging.debug("curClassStr=%s", curClassStr)
        curClassContent = curClassStr
        logging.debug("curClassContent=%s", curClassContent)
        classFilename = "%s.%s.swift" % (libName, className)
        logging.debug("classFilename=%s", classFilename)
        curOutputFullPath = os.path.join(gOutputFoler_swift_class, classFilename)

        # for debug
        if os.path.exists(curOutputFullPath):
            logging.debug("! existed curOutputFullPath=%s", curOutputFullPath)

        saveTextToFile(curOutputFullPath, curClassContent)

    totalNum = len(classStrList)
    return totalNum

def dumpSwift_crifan(out):
    totalNum_swift_protocol = dumpSwift_crifan_protocol(out)
    totalNum_swift_class =  dumpSwift_crifan_class(out)
    summaryDict_swift = {
        "protocol": totalNum_swift_protocol,
        "class": totalNum_swift_class,
        "total": totalNum_swift_protocol + totalNum_swift_class,
    }
    return summaryDict_swift

def dumpSwift(inputfile, outputFolder, arches, demangle):
    strline = f'./dsdump -a {arches} --swift --verbose=5 "{inputfile}"'
    p = subprocess.Popen(strline, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = p.communicate()[0].decode('utf-8', 'ignore')
    saveTextToFile("debugging/swift/out.coffee", out)

    # dumpSwift_origin(out, outputFolder)
    summaryDict_swift = dumpSwift_crifan(out)
    return summaryDict_swift


def swiftDemangle(className):
    if className.startswith('_'):
        if '(' in className and ')' in className:
            className = className.split('(')[0]
        p = subprocess.Popen(
            f'xcrun swift-demangle --simplified --compact {className}',
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        out = p.communicate()[0].decode('utf-8', 'ignore').strip()
        if len(out) > 2:
            return out
    return className

def printSummary(summaryDict_objc, summaryDict_swift):
    summaryDict = {
        "objc": summaryDict_objc,
        "swift": summaryDict_swift,
        "total": summaryDict_objc["total"] + summaryDict_swift["total"]
    }
    logging.info("="*40 + " Summary " + "="*40)
    logging.info("All:\t\t\t\t%d", summaryDict["total"])
    logging.info("  ObjC:\t\t\t%d", summaryDict_objc["total"])
    logging.info("    protocol:\t\t\t%d", summaryDict_objc["protocol"])
    logging.info("    class:\t\t\t%d", summaryDict_objc["class"])
    logging.info("    category:\t\t\t%d", summaryDict_objc["category"])
    logging.info("  Swift:\t\t\t%d", summaryDict_swift["total"])
    logging.info("    protocol:\t\t\t%d", summaryDict_swift["protocol"])
    logging.info("    class(+enum+struct):\t%d", summaryDict_swift["class"])

def main(argv):
    inputfile = ''
    outputFolder = ''
    arches = 'arm64'
    demangle = False
    try:
        opts, args = getopt.getopt(argv, "hi:o:a:d", ["ifile=", "ofile=", "arches=", "demangle"])
    except getopt.GetoptError:
        print('')
        sys.exit(0)

    for (opt, arg) in opts:
        if opt == '-h':
            print(howToUse)
            sys.exit(1)
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputFolder = arg
        elif opt in ("-a", "--arches"):
            arches = arg
            if arches not in ['arm64', 'armv7']:
                print(howToUse)
                sys.exit(1)
        elif opt in ("-d", "--demangle"):
            demangle = True

    if os.path.isfile(inputfile) and outputFolder != '':
        if outputFolder.endswith('/'):
            outputFolder[:-1]
        
        initOutputFolder(outputFolder)

        summaryDict_objc = dumpObjectiveC(inputfile, outputFolder, arches, demangle)
        summaryDict_swift = dumpSwift(inputfile, outputFolder, arches, demangle)
        printSummary(summaryDict_objc, summaryDict_swift)
    else:
        print(howToUse)
        sys.exit(2)

if __name__ == "__main__":
    # init logging
    crifanLogging.autoInitLog(__file__)

    main(sys.argv[1:])
