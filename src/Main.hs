{-# LANGUAGE RecordWildCards #-}

module Main where

import Data.Monoid
import Data.Word
import Data.Void
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Char
import Data.Bifunctor
import Control.Monad

import Text.Megaparsec hiding (option)
import Text.Megaparsec.Char
import qualified Text.Megaparsec.Char.Lexer as L
import Hexdump
import Network.Pcap
import Options.Applicative
import Data.Serialize

import Data.Ethernet
import Data.IP
import Data.CSum

------------------------------------------------------------------------------
--Expresssion parser
------------------------------------------------------------------------------

space' = L.space space1 (L.skipLineComment "//") (L.skipBlockComment "/*" "*/")

lexeme = L.lexeme space'

symbol = L.symbol space'

parens = between (symbol "(") (symbol ")")

quotes = between (symbol "\"") (symbol "\"")

squotes = between (symbol "'") (symbol "'")

decimal = lexeme L.decimal

colon = symbol ":"

dot = symbol "."

hexPair :: Parsec Void String Word8
hexPair = do
    c1 <- hexDigitChar
    c2 <- hexDigitChar
    return $ fromIntegral (digitToInt c1) * 16 + fromIntegral (digitToInt c2)

expression 
    =   concat <$> (replicate <$> (try (decimal <* symbol "*")) <*> expressions)
    <|> quotes (many (fromIntegral . fromEnum <$> (notChar '"')))
    <|> squotes (many (fromIntegral . fromEnum <$> (notChar '\'')))
    <|> lexeme (pure <$> hexPair)
    <|> parens expressions

expressions = concat <$> some expression

topParser :: Parsec Void String ByteString
topParser = do
    res <- expressions
    eof
    return $ BS.pack res

------------------------------------------------------------------------------
--Network param parser
------------------------------------------------------------------------------

parseEtherAddress :: Parsec Void String Ethernet
parseEtherAddress 
    =  Ethernet 
    <$> hexPair
    <*  colon <*> hexPair
    <*  colon <*> hexPair
    <*  colon <*> hexPair
    <*  colon <*> hexPair
    <*  colon <*> hexPair

parseIPAddress :: Parsec Void String IPv4
parseIPAddress 
    =   func 
    <$> decimal
    <*  dot <*> decimal
    <*  dot <*> decimal
    <*  dot <*> decimal
    where
    func w x y z = IPv4 $ fromIntegral $ w * 2^24 + x * 2^16 + y * 2^8 + z

broadcastEther = Ethernet 0xff 0xff 0xff 0xff 0xff 0xff

optionify :: Parsec Void String a -> ReadM a
optionify parser = eitherReader $ first parseErrorPretty . parse parser "CMDLINE"

dataOptionParser :: Parser ByteString
dataOptionParser = argument (optionify topParser) (metavar "DATA" <> value mempty)

parseEthernetHdr :: Parser EthernetHeader
parseEthernetHdr 
    =   EthernetHdr
    <$> option (optionify parseEtherAddress) (short 'd' <> long "dest"      <> help "Destination MAC address" <> value broadcastEther <> showDefault)
    <*> option (optionify parseEtherAddress) (short 's' <> long "source"    <> help "Source MAC address"      <> value broadcastEther <> showDefault)
    <*> pure Nothing
    <*> option (optionify L.hexadecimal)     (short 't' <> long "ethertype" <> help "Ether type"              <> value 0x0800         <> showDefault)

parseIPHeader :: Parser IPv4Header
parseIPHeader 
    =   IPv4Hdr
    <$> pure 5
    <*> pure 4
    <*> pure 0
    <*> option auto (short 'l' <> long "length" <> help "length" <> value 20 <> showDefault)
    <*> pure 0
    <*> pure []
    <*> pure 0
    <*> pure 0
    <*> option auto (short 'p' <> long "protocol" <> help "protocol" <> value 0x11 <> showDefault)
    <*> pure (zeroCSum)
    <*> option (optionify parseIPAddress) (short 's' <> long "source" <> help "Source IP address"      <> value (IPv4 0x7f000001) <> showDefault)
    <*> option (optionify parseIPAddress) (short 'd' <> long "dest"   <> help "Destination IP address" <> value (IPv4 0x7f000001) <> showDefault)

data Layer3
    = IPCommand        IPv4Header ByteString
    | RawLayer3Command ByteString

putLayer3 :: Layer3 -> ByteString
putLayer3 (IPCommand        hdr dat) = runPut (put hdr) <> dat
putLayer3 (RawLayer3Command dat)     = dat

layer3Parser :: Parser Layer3
layer3Parser = hsubparser $ mconcat [
        command "ip"  (info (IPCommand        <$> parseIPHeader <*> dataOptionParser) (progDesc "Send IP packet")),
        command "raw" (info (RawLayer3Command <$> dataOptionParser)                   (progDesc "Raw payload"))
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

