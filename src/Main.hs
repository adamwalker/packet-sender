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

broadcastEther = Ethernet 0xff 0xff 0xff 0xff 0xff 0xff

optionify :: Parsec Void String a -> ReadM a
optionify parser = eitherReader $ first parseErrorPretty . parse parser "CMDLINE"

dataOptionParser :: Parser ByteString
dataOptionParser = argument (optionify topParser) (metavar "DATA")

parseEthernetHdr :: Parser EthernetHeader
parseEthernetHdr 
    =   EthernetHdr
    <$> option (optionify parseEtherAddress) (short 'd' <> long "dest"      <> help "Destination MAC address" <> value broadcastEther <> showDefault)
    <*> option (optionify parseEtherAddress) (short 's' <> long "source"    <> help "Source MAC address"      <> value broadcastEther <> showDefault)
    <*> pure Nothing
    <*> option (optionify L.hexadecimal)     (short 't' <> long "ethertype" <> help "Ether type"              <> value 0x0800         <> showDefault)

data Command
    = EthernetCommand  EthernetHeader ByteString
    | RawLayer2Command ByteString

putCommand :: Command -> ByteString
putCommand (EthernetCommand  hdr dat) = runPut (put hdr) <> dat
putCommand (RawLayer2Command dat)     = dat

parseCommand :: Parser Command
parseCommand = hsubparser $ mconcat [
        command "ether" (info (EthernetCommand  <$> parseEthernetHdr <*> dataOptionParser) (progDesc "Send ethernet packet")),
        command "raw"   (info (RawLayer2Command <$> dataOptionParser) (progDesc "Raw packet"))
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

