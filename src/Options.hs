module P2P.Options where

import           System.Console.GetOpt
import           System.Environment (getArgs)
import           System.Exit (exitFailure)

import           P2P.Types

defaultOptions :: Options
defaultOptions = Options
  { verbose     = False
  , connectAddr = Nothing
  , listenPort  = defaultPort
  , bootstrap   = False
  }

options :: [OptDescr (Options -> Options)]
options =
  [ Option "v" ["verbose"] (NoArg $ \o -> o { verbose = True })
      "Print additional debug messages"

  , Option "c" ["connect"] (ReqArg parseAddr "HOST:PORT")
      "Connect to the given address on startup"

  , Option "p" ["port"]
      (ReqArg (\p o -> o { listenPort = fromInteger (read p) }) "PORT") $
      "Listen on the following port instead of the default (" ++
        show defaultPort ++ ")"

  , Option "b" ["bootstrap"] (NoArg  $ \o -> o { bootstrap = True })
      "Start up an initial network instead of connecting"
  ]

parseAddr :: String -> Options -> Options
parseAddr s o = o { connectAddr = Just (addr, port) }
  where
    (addr, port') = break (==':') s

    port = case port' of
      []  -> defaultPort
      _:p -> fromInteger $ read p

getOptions :: IO Options
getOptions = do
  args <- getArgs
  let (opts, _, errs) = getOpt Permute options args

  case errs of
    [] -> return ()
    es -> mapM_ (\e -> putStrLn $ "[!] " ++ e) es >> showUsage >> exitFailure

  return $ foldr ($) defaultOptions opts

showUsage :: IO ()
showUsage = putStrLn usage
  where
    usage' = usageInfo "Usage: p2p-chat [OPTIONS..]" options
    usage  = unlines . map ("[?] " ++) $ lines usage'
