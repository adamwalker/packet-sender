module PacketSender.CmdLine where

import Data.Void
import Data.Monoid
import Data.Bifunctor

import Options.Applicative

import Text.Megaparsec hiding (option)
import qualified Text.Megaparsec.Char.Lexer as L

import Data.Ethernet
import Data.IP
import Data.UDP
import Data.CSum

import PacketSender.Expression

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

parseEthernetHdr :: Parser EthernetHeader
parseEthernetHdr 
    =   EthernetHdr
    <$> option (optionify parseEtherAddress)       (short 'd' <> long "dest"      <> help "Destination MAC address" <> value broadcastEther <> showDefault)
    <*> option (optionify parseEtherAddress)       (short 's' <> long "source"    <> help "Source MAC address"      <> value broadcastEther <> showDefault)
    <*> optional (option (optionify L.hexadecimal) (short 'v' <> long "vlan-tag"  <> help "VLAN tag"))
    <*> option (optionify L.hexadecimal)           (short 't' <> long "ethertype" <> help "Ether type"              <> value 0x0800         <> showDefault)

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
    <*> pure zeroCSum
    <*> option (optionify parseIPAddress) (short 's' <> long "source" <> help "Source IP address"      <> value (IPv4 0x7f000001) <> showDefault)
    <*> option (optionify parseIPAddress) (short 'd' <> long "dest"   <> help "Destination IP address" <> value (IPv4 0x7f000001) <> showDefault)

parseUDPHeader :: Parser UDPHeader
parseUDPHeader  
    =   UDPHdr
    <$> option (UDPPort <$> auto) (short 's' <> long "source" <> help "Source port"      <> value (UDPPort 0) <> showDefault)
    <*> option (UDPPort <$> auto) (short 'd' <> long "dest"   <> help "Destination port" <> value (UDPPort 0) <> showDefault)
    <*> option auto (short 'l' <> long "length" <> help "length" <> value 0 <> showDefault)
    <*> (pure zeroCSum)

