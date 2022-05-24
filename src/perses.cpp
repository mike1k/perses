#include "perses.hpp"
#include <argparse/argparse.hpp>


template<int BitSize>
void createApplication(perses::X86BinaryApplication<BitSize>* app, argparse::ArgumentParser& args)
{
	spdlog::stopwatch sw;
	int numSeconds = 0;
	float numMinutes = 0.f;

	if (args.is_used("--rets"))
		perses::buildKnownRetGadgets(app);

	std::string_view sectionName = ".perses";

	if (auto param = args.present<std::string>("--section-name"))
		sectionName = *param;

	if (auto param = args.present<std::string>("--map"))
	{
		std::filesystem::path path = *param;
		
		if (!std::filesystem::exists(path))
		{
			logger()->critical("Unable to parse map file, non existent!");
			goto Delete;
		}

		if (path.extension().string() == ".ida")
			app->linkMapFile(perses::MapFileType::kIDAPro, *param);
		else
			app->linkMapFile(perses::MapFileType::kMSVC, *param);
	}

	if (auto param = args.present<std::string>("--list"))
	{
		std::filesystem::path path = *param;

		if (!std::filesystem::exists(path))
		{
			logger()->critical("Unable to parse list file, non existent!");
			goto Delete;
		}

		app->parseFunctionList(*param);
	}

	if (auto param = args.present<std::vector<std::string>>("-a"))
	{
		for (auto& uaddr : *param)
		{
			perses::u64 addr = strtoull(uaddr.c_str(), nullptr, 16);
			if (addr > 0)
				app->addRoutineByAddress(addr, PERSES_MARKER_MUTATION);
		}
	}

	if (auto param = args.present<std::vector<std::string>>("-s"))
	{
		if (app->hasMapFile())
		{
			for (auto& sym : *param)
			{
				app->addRoutineBySymbol(sym, PERSES_MARKER_MUTATION);
			}
		}
		else
		{
			logger()->critical("Unable to use symbols argument without a linked .MAP file!");
			goto Delete;
		}
	}

	if (args.is_used("--scan"))
		app->scanForMarkers();

	if (app->getRoutines().empty())
	{
		logger()->critical("Unable to mutate: no routines in queue.");
		goto Delete;
	}

	app->transformRoutines();
	app->compile(sectionName);

	logger()->info("Mutated {} routines.", app->getRoutines().size());

	numSeconds = std::chrono::duration_cast<std::chrono::seconds>(sw.elapsed()).count();
	numMinutes = (float)numSeconds / 60.f;

	if (numSeconds > 60)
		logger()->info("It took {} minutes and {} seconds to complete this operation.", (int)(numSeconds / 60), (int)((float)(numMinutes - (int)numMinutes) * 60.f));
	else
		logger()->info("It took {} seconds to complete this operation.", numSeconds);

Delete:
	delete app;
}


int main(int argc, char* argv[])
{
	argparse::ArgumentParser args("PERSES");
	void* app = nullptr;

	args.add_argument("-f", "--file")
		.help("Input file path.")
		.required();
	args.add_argument("-a", "--address")
		.help("Address(es) to mutate")
		.remaining();
	args.add_argument("-s", "--symbol")
		.help("Symbol(s) to mutate (requires .MAP)")
		.remaining();
	args.add_argument("--list")
		.help("Parsable function list (NOTE: all entries in the list will be added).");
	args.add_argument("--map")
		.help("Parsable map file (NOTE: IDA Pro .MAP files must have their extension named as \".ida\").");
	args.add_argument("--section-name")
		.help("Section name.");
	args.add_argument("--rets")
		.help("Use RET gadgets.")
		.default_value(false)
		.implicit_value(true);
	args.add_argument("--scan")
		.help("Scan for protection markers.")
		.default_value(false)
		.implicit_value(true);

	if (argc <= 1)
	{
		args.print_help();
		return 1;
	}

	try {
		args.parse_args(argc, argv);
	}
	catch (const std::runtime_error& err) {
		args.print_help();
		return 1;
	}

	logger()->debug("PERSES Code Protection Engine");

	std::string filepath = args.get<std::string>("-f");

	if (!std::filesystem::exists(filepath))
	{
		logger()->critical("Unable to find file: {}.", filepath);
		return 1;
	}

	// Determine arch. type automatically.
	DWORD type = 0ul;

	if (!GetBinaryTypeA(filepath.c_str(), &type) && GetLastError() != ERROR_BAD_EXE_FORMAT)
	{
		logger()->critical("Are you sure this is a executable file?");
		return 1;
	}

	if (type == SCS_64BIT_BINARY)
	{
		createApplication(new perses::X86BinaryApplication<PERSES_64BIT>(filepath), args);
	}
	else
	{
		createApplication(new perses::X86BinaryApplication<PERSES_32BIT>(filepath), args);
	}

	return 0;
}

std::shared_ptr<spdlog::logger> logger()
{
	static std::shared_ptr<spdlog::logger> log = nullptr;

	if (!log)
	{
		log = spdlog::stdout_color_mt("console");
		log->set_level(spdlog::level::debug);
		log->set_pattern("[%^PERSES%$] %v");

		spdlog::set_error_handler([](const std::string& msg) { printf("*** LOG ERROR: %s ***\n", msg.c_str()); });
	}

	return log;
}