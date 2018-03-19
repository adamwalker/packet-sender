{-# LANGUAGE RecordWildCards #-}

module Main where

import Data.Monoid
import Data.ByteString (ByteString)
import Control.Monad

import Hexdump
import Network.Pcap
import Options.Applicative
import Data.Serialize

import Data.Ethernet
import Data.IP
import Data.UDP

import PacketSender.CmdLine
import PacketSender.Expression

dataOptionParser :: Parser ByteString
dataOptionParser = argument (optionify topParser) (metavar "DATA" <> value mempty)

data Layer4
    = UDPCommand       UDPHeader ByteString
    | RawLayer4Command ByteString

putLayer4 :: Layer4 -> ByteString
putLayer4 (UDPCommand       hdr dat) = runPut (put hdr) <> dat
putLayer4 (RawLayer4Command dat)     = dat

layer4Parser :: Parser Layer4
layer4Parser = hsubparser $ mconcat [
        command "udp" (info (UDPCommand       <$> parseUDPHeader <*> dataOptionParser) (progDesc "Send UDP packet")),
        command "raw" (info (RawLayer4Command <$> dataOptionParser)                    (progDesc "Raw payload"))
    ]

data Layer3
    = IPCommand        IPv4Header Layer4
    | RawLayer3Command ByteString

putLayer3 :: Layer3 -> ByteString
putLayer3 (IPCommand        hdr dat) = runPut (put hdr) <> putLayer4 dat
putLayer3 (RawLayer3Command dat)     = dat

layer3Parser :: Parser Layer3
layer3Parser = hsubparser $ mconcat [
        command "ip"  (info (IPCommand        <$> parseIPHeader <*> layer4Parser) (progDesc "Send IP packet")),
        command "raw" (info (RawLayer3Command <$> dataOptionParser)               (progDesc "Raw payload"))
    ]

data Command
    = EthernetCommand  EthernetHeader Layer3
    | RawLayer2Command ByteString

putCommand :: Command -> ByteString
putCommand (EthernetCommand  hdr dat) = runPut (put hdr) <> putLayer3 dat
putCommand (RawLayer2Command dat)     = dat

parseCommand :: Parser Command
parseCommand = hsubparser $ mconcat [
        command "ether" (info (EthernetCommand  <$> parseEthernetHdr <*> layer3Parser) (progDesc "Send ethernet packet")),
        command "raw"   (info (RawLayer2Command <$> dataOptionParser)                  (progDesc "Raw payload"))
    ]

data Options = Options {
    intf    :: String,
    verbose :: Bool,
    dryRun  :: Bool,
    toSend  :: Command
}

func Options{..} = do

    let serialized = putCommand toSend

    when (verbose || dryRun) $ putStrLn $ "\n" ++ prettyHex serialized

    unless dryRun $ do

        -- open device
        dev <- openLive intf 65535 False 0

        -- send
        sendPacketBS dev serialized

main = customExecParser (prefs $ showHelpOnError) opts >>= func 
    where 
    opts = info (helper <*> parseOpts) (fullDesc <> header "Send packets")

    parseOpts 
        =   Options
        <$> strOption (short 'i' <> long "intf" <> metavar "INTF" <> help "Network interface to send on" <> showDefault <> value "lo")
        <*> switch (short 'v' <> long "verbose" <> help "Print the packet contents to stdout before sending")
        <*> switch (short 'n' <> long "dry-run" <> help "Don't actually send the packet, just print it")
        <*> parseCommand

