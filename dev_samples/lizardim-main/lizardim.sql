-- --------------------------------------------------------

--
-- Struttura della tabella `apps`
--

CREATE TABLE IF NOT EXISTS `apps` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `path` varchar(60) NOT NULL,
  `name` varchar(150) NOT NULL,
  `desc` varchar(255) NOT NULL,
  `position` int(11) NOT NULL,
  `owner` int(11) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=33 ;

--
-- Dump dei dati per la tabella `apps`
--

INSERT INTO `apps` (`id`, `path`, `name`, `desc`, `position`, `owner`) VALUES
(2, 'apache', 'Apache', 'Gestisci il server Apache', 2, -1),
(3, 'inventor', 'App Creator', 'Crea e modifica le app per Lizard', 1, -1),
(29, 'settings', 'Settings', 'Gestisci il tuo account Lizard!', 0, 1),
(30, 'turnmeon', 'TurnMeOn', 'Avvia, riavvia e termina i principali servizi.', 0, 1),
(31, 'terminal', 'Terminal', 'Console via SSH', 0, 1),
(32, 'prova', 'prova', 'prova', 0, 1);

-- --------------------------------------------------------

--
-- Struttura della tabella `connectino`
--

CREATE TABLE IF NOT EXISTS `connectino` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user` int(11) NOT NULL,
  `pc-user` varchar(100) NOT NULL,
  `ip` varchar(15) NOT NULL,
  `password` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=12 ;

--
-- Dump dei dati per la tabella `connectino`
--

INSERT INTO `connectino` (`id`, `user`, `pc-user`, `ip`, `password`, `name`) VALUES
(8, 1, 'lizarduser', '127.0.0.1', 'lizardproject', 'LocalCloud'),
(10, 1, 'pc-userr', '127.0.0.1', 'test', 'ComputerCasa'),
(11, 1, 'barra', '214.123.213.43', 'paolo', 'Scuola');

-- --------------------------------------------------------

--
-- Struttura della tabella `revisions`
--

CREATE TABLE IF NOT EXISTS `revisions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `rev` int(11) NOT NULL,
  `app` int(11) NOT NULL,
  `ver` varchar(10) NOT NULL,
  `desc` varchar(255) NOT NULL,
  `inmenu` int(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=40 ;

--
-- Dump dei dati per la tabella `revisions`
--

INSERT INTO `revisions` (`id`, `rev`, `app`, `ver`, `desc`, `inmenu`) VALUES
(1, 1, 28, '0.1', 'niente', 1),
(2, 0, 0, '0.1', 'desc', 1),
(6, 586115867, 37, '0.1', 'cio', 1),
(7, 2, 29, '0.1', 'Work in progress...', 1),
(8, 3, 30, '0.1', 'Turn me on!', 1),
(29, 215560516, 30, '0.2', '', 1),
(37, 1736104685, 28, '0.2', '', 1),
(38, 93993801, 31, '0.1', 'Console via SSH', 1),
(39, 995999066, 32, '0.1', 'prova', 1);

-- --------------------------------------------------------

--
-- Struttura della tabella `store`
--

CREATE TABLE IF NOT EXISTS `store` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app` int(11) NOT NULL,
  `rev` int(11) NOT NULL,
  `state` int(11) NOT NULL,
  `desc` text NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1 AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Struttura della tabella `user`
--

CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `password` varchar(60) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=2 ;

--
-- Dump dei dati per la tabella `user`
--

INSERT INTO `user` (`id`, `email`, `password`) VALUES
(1, 'test@test.com', 'test');